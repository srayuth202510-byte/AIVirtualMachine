"""Prepare bounded native C observations; never interpret model output as commands."""
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

MAX_SOURCE = 8192
IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]{0,63}\Z")
ALLOWED = {
    "FunctionDecl", "ParmVarDecl", "CompoundStmt", "DeclStmt", "VarDecl",
    "IfStmt", "ForStmt", "WhileStmt", "DoStmt", "ReturnStmt", "NullStmt",
    "BreakStmt", "ContinueStmt", "BinaryOperator", "CompoundAssignOperator",
    "UnaryOperator", "IntegerLiteral", "ImplicitCastExpr", "ParenExpr",
    "DeclRefExpr", "ConditionalOperator",
}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def identifier(name):
    if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name.startswith("aivm_trace_"):
        raise ValueError("expected a plain C identifier outside the aivm_trace_ namespace")
    return name


def span(node):
    location = node["range"]
    first, last = location["begin"], location["end"]
    if "offset" not in first or "offset" not in last:
        raise ValueError("macro or unavailable source range")
    return first["offset"], last["offset"] + last["tokLen"]


def target_name(node):
    while node["kind"] == "ParenExpr":
        node = node["inner"][0]
    if node["kind"] != "DeclRefExpr" or node["referencedDecl"]["kind"] not in ("VarDecl", "ParmVarDecl"):
        raise ValueError("only updates to plain local integer variables are supported")
    return identifier(node["referencedDecl"]["name"])


def c_integer(value):
    return "(-2147483647 - 1)" if value == -(2 ** 31) else str(value)


def prepare(source, function, inputs, max_events=32, compiler=None, argument_order=None):
    """ใช้ Clang AST ระบุตำแหน่ง แล้วให้ native C เป็นผู้คำนวณค่าจริง."""
    if function is not None:
        identifier(function)
    if function == "main" or not isinstance(source, bytes) or not 1 <= len(source) <= MAX_SOURCE:
        raise ValueError("expected one non-main C function, at most 8192 source bytes")
    text = source.decode("utf-8")
    if "#" in text or "\\" in text or "aivm_trace_" in text:
        raise ValueError("preprocessor directives, escapes and reserved trace names are unsupported")
    if type(max_events) is not int or not 4 <= max_events <= 64:
        raise ValueError("max_events must be 4..64")
    if not isinstance(inputs, dict) or any(type(v) is not int or not -(2 ** 31) <= v < 2 ** 31 for v in inputs.values()):
        raise ValueError("inputs must map parameter names to signed 32-bit integers")
    compiler = compiler or shutil.which("clang")
    if compiler is None:
        raise ValueError("clang is required to prepare source locations")
    compiler = str(Path(compiler).resolve())
    with open(compiler, "rb") as stream:
        compiler_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    command = [compiler, "-x", "c", "-std=c11", "-Werror=unsequenced", "-Werror=return-type",
               "-Werror=uninitialized", "-Xclang", "-ast-dump=json", "-fsyntax-only", "-"]
    parsed = subprocess.run(command, input=source, capture_output=True, timeout=15, check=False)
    if parsed.returncode or len(parsed.stdout) > 2 * 1024 * 1024:
        raise ValueError("unsupported or invalid C source: " + parsed.stderr.decode(errors="replace")[:1500])
    tree = json.loads(parsed.stdout)
    declarations = [n for n in tree.get("inner", []) if not n.get("isImplicit")]
    if len(declarations) != 1 or declarations[0]["kind"] != "FunctionDecl":
        raise ValueError("source must contain exactly the selected function and no global declarations")
    target = declarations[0]
    if function is None:
        function = identifier(target.get("name"))
    if target.get("name") != function or function == "main":
        raise ValueError("source must contain exactly the selected non-main function")
    if not target["type"]["qualType"].startswith("int (") or target.get("variadic"):
        raise ValueError("only functions returning int are supported")
    parameters = [identifier(n.get("name")) for n in target.get("inner", []) if n["kind"] == "ParmVarDecl"]
    logical_input = dict(inputs)
    if argument_order:
        if len(argument_order) != len(parameters) or len(set(argument_order)) != len(argument_order) or set(argument_order) != set(inputs):
            raise ValueError("argument_order must name each input key exactly once")
        inputs = dict(zip(parameters, (inputs[key] for key in argument_order)))
    if len(parameters) > 8 or set(inputs) != set(parameters):
        raise ValueError("input keys must match the function's named int parameters (at most eight)")
    if not any(n["kind"] == "CompoundStmt" for n in target.get("inner", [])):
        raise ValueError("function body is missing")
    sites, wrappers, replacements = [], [], {}

    def site(node, kind, name):
        start, end = span(node)
        if not 0 <= start < end <= len(source) or len(sites) >= 128:
            raise ValueError("invalid or excessive instrumentation sites")
        number = len(sites) + 1
        sites.append({"id": number, "kind": kind, "name": name,
                      "line": source[:start].count(b"\n") + 1,
                      "column": start - source.rfind(b"\n", 0, start),
                      "source": source[start:end].decode()[:160]})
        return number

    def wrap(node, kind, name):
        number = site(node, kind, name)
        start, end = span(node)
        wrappers.append((start, end, len(wrappers), f"aivm_trace_value({number}, (".encode(), b"))"))

    def visit(node):
        kind = node.get("kind")
        if kind is None:
            return
        if kind not in ALLOWED:
            raise ValueError(f"unsupported C construct: {kind}")
        if kind != "FunctionDecl" and node.get("type", {}).get("qualType", "int") != "int":
            raise ValueError("only plain int expressions and variables are supported")
        if kind in ("FunctionDecl", "ParmVarDecl", "VarDecl"):
            identifier(node.get("name"))
            if node.get("storageClass") or node.get("tls"):
                raise ValueError("storage-qualified declarations are unsupported")
        children = node.get("inner", [])
        if kind == "VarDecl":
            if len(children) != 1:
                raise ValueError("local variables must have an initializer")
            wrap(children[0], "initialize", node["name"])
        elif kind == "ReturnStmt":
            if len(children) != 1:
                raise ValueError("return must have an int value")
            wrap(children[0], "return", "return")
        elif kind in ("IfStmt", "WhileStmt", "DoStmt", "ForStmt"):
            condition = children[2] if kind == "ForStmt" else children[-1] if kind == "DoStmt" else children[0]
            if not condition.get("kind"):
                raise ValueError("loops must have an explicit condition")
            wrap(condition, "condition", kind)
        elif kind == "CompoundAssignOperator" or (kind == "BinaryOperator" and node.get("opcode") == "="):
            wrap(node, "assign", target_name(children[0]))
        elif kind == "UnaryOperator":
            operation = node["opcode"]
            if operation in ("++", "--"):
                name = target_name(children[0])
                number = site(node, "update", name)
                start, end = span(node)
                delta = 1 if operation == "++" else -1
                replacements[start] = (end, f"aivm_trace_update({number}, &{name}, {delta}, {int(node.get('isPostfix', False))})".encode())
            elif operation not in ("+", "-", "!", "~"):
                raise ValueError(f"unsupported unary operator: {operation}")
        for child in children:
            visit(child)

    parameter_sites = [site(n, "parameter", n["name"]) for n in target["inner"] if n["kind"] == "ParmVarDecl"]
    visit(target)
    opens, closes = {}, {}
    for start, end, order, prefix, suffix in wrappers:
        opens.setdefault(start, []).append((-end, order, prefix))
        closes.setdefault(end, []).append((-start, -order, suffix))
    rewritten, position = [], 0
    while position <= len(source):
        rewritten.extend(item[2] for item in sorted(closes.get(position, [])))
        rewritten.extend(item[2] for item in sorted(opens.get(position, [])))
        if position == len(source):
            break
        if position in replacements:
            position, replacement = replacements[position]
            rewritten.append(replacement)
        else:
            rewritten.append(source[position:position + 1])
            position += 1
    arguments = ",".join(c_integer(inputs[name]) for name in parameters)
    main = f'\nint main(void){{int value={function}({arguments});printf("AIVM_RESULT %d\\n",value);return 0;}}\n'
    original = b"#include <stdio.h>\n" + source + main.encode()
    # helper รับ expression value เพียงครั้งเดียว; postfix update คืนค่าเดิมตาม C semantics
    helper = f'''#include <stdio.h>
#include <stdlib.h>
static unsigned aivm_trace_count;
static int aivm_trace_value(int site,int value){{
    if(aivm_trace_count++ >= {max_events}){{puts("AIVM_TRACE_TRUNCATED");fflush(stdout);_Exit(75);}}
    printf("AIVM_TRACE {{\\"site\\":%d,\\"value\\":%d}}\\n",site,value);
    return value;
}}
static int aivm_trace_update(int site,int *value,int delta,int postfix){{
    int previous=*value; *value+=delta;
    aivm_trace_value(site,*value);
    return postfix ? previous : *value;
}}
'''
    entry = "".join(f"aivm_trace_value({number},{c_integer(inputs[name])});" for number, name in zip(parameter_sites, parameters))
    traced_main = main.replace("{int value=", "{" + entry + "int value=", 1)
    traced = helper.encode() + b"".join(rewritten) + traced_main.encode()
    manifest = {"schema": 1, "kind": "native_integer_function_trace", "function": function,
                "function_range": list(span(target)),
                "input": inputs, "logical_input": logical_input, "parameters": parameters, "max_events": max_events,
                "source_sha256": digest(source), "original_sha256": digest(original),
                "traced_sha256": digest(traced), "sites": sites,
                "parser": {"path": compiler, "sha256": compiler_hash, "argv": command[1:]},
                "scope": "One standalone C function, int parameters/locals/result, defined integer behavior only; observations are diagnostic, not repair verification."}
    return manifest, original, traced


def validate_measurements(bundle, measurement, audits):
    """คืน trace เฉพาะเมื่อ native measurements/audit และค่าคืนสองชุดตรงกัน."""
    import release_evidence as evidence
    if measurement.get("kind") != "operator_trace_measurement_not_repair":
        raise ValueError("not an operator trace measurement")
    parsed = []
    for label in ("original", "traced"):
        row = measurement[label]
        records = evidence.audit_records(audits[label])
        if not evidence.valid_outcome(row["outcome"], row["task_contract"], row["verification"], records):
            raise ValueError("measurement audit/outcome mismatch")
        checks = row["checks"]
        snapshot = row["snapshot"]
        if (not evidence.audited_value(snapshot, records, action="native-trace-observation", rule="native-output-snapshot")
                or snapshot["task_id"] != row["task_contract"]["task_id"] or snapshot["label"] != label
                or snapshot["source_sha256"] != bundle[label + "_sha256"]
                or snapshot["checks_sha256"] != digest(evidence.canonical(checks))
                or snapshot["verification_audit_id"] != (row["verification"] or {}).get("audit_id")):
            raise ValueError("measurement output snapshot mismatch")
        if len(checks) != 3 or not all(check["ok"] for check in checks[:2]):
            raise ValueError("measurement compilation failed")
        output = checks[-1]["output"]
        if "AIVM_TRACE_TRUNCATED" in output:
            raise ValueError("trace truncated; no complete observation is available")
        values = re.findall(r"(?m)^AIVM_RESULT (-?\d+)$", output)
        if not checks[-1]["ok"] or len(values) != 1 or row["outcome"]["verification"] != "passed":
            raise ValueError("measurement did not complete successfully")
        parsed.append((int(values[0]), output))
    if parsed[0][0] != parsed[1][0]:
        raise ValueError("instrumented source changed the observed result")
    sites = {site["id"]: site for site in bundle["sites"]}
    events = []
    for payload in re.findall(r"(?m)^AIVM_TRACE (.+)$", parsed[1][1]):
        event = evidence.decode_json(payload)
        if set(event) != {"site", "value"} or type(event["site"]) is not int or event["site"] not in sites or type(event["value"]) is not int:
            raise ValueError("invalid trace event")
        events.append(dict(sites[event["site"]], value=event["value"]))
    if not events or len(events) > bundle["max_events"] or events[-1]["kind"] != "return" or events[-1]["value"] != parsed[0][0]:
        raise ValueError("incomplete or inconsistent native trace")
    return {"schema": 1, "kind": "observed_native_trace", "source_sha256": bundle["source_sha256"],
            "function": bundle["function"], "input": bundle["input"], "actual": parsed[0][0],
            "events": events, "original_and_traced_return_match": True, "repair_verified": False}


def render(trace):
    lines = ["Observed execution (diagnostic data from an instrumented copy):",
             f"Function: {trace['function']}", "Input: " + json.dumps(trace["input"], sort_keys=True),
             "Source SHA256: " + trace["source_sha256"]]
    for i, event in enumerate(trace["events"], 1):
        label = "return" if event["kind"] == "return" else event["kind"] + " " + event["name"]
        lines.append(f"{i}. line {event['line']}: {label} = {event['value']}")
    lines.append(f"Actual returned value: {trace['actual']}")
    return "\n".join(lines) + "\n"
