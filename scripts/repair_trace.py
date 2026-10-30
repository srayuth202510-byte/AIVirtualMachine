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
    "UnaryOperator", "IntegerLiteral", "CharacterLiteral", "ImplicitCastExpr",
    "ParenExpr", "DeclRefExpr", "ConditionalOperator", "CStyleCastExpr",
    "ArraySubscriptExpr",
}
SUPPORTED_INTEGER_TYPES = {
    "int", "unsigned int", "unsigned", "_Bool",
    "const int", "char", "const char", "signed char", "unsigned char",
}
SUPPORTED_POINTER_TYPES = {"const int *", "int *", "const char *", "char *"}


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


def target_name(node, allow_subscript=False):
    while node["kind"] in ("ParenExpr", "ImplicitCastExpr"):
        node = node["inner"][0]
    if allow_subscript and node["kind"] == "ArraySubscriptExpr":
        return target_name(node["inner"][0], False)
    if node["kind"] != "DeclRefExpr" or node["referencedDecl"]["kind"] not in ("VarDecl", "ParmVarDecl"):
        raise ValueError("only updates to plain local integer variables are supported")
    return identifier(node["referencedDecl"]["name"])


def c_integer(value, ptype="int"):
    if ptype in ("unsigned int", "unsigned"):
        return f"{value}u"
    return "(-2147483647 - 1)" if value == -(2 ** 31) else str(value)


def c_string(value):
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def valid_input_value(value):
    if type(value) is int:
        return -(2 ** 31) <= value < 2 ** 32
    if isinstance(value, list):
        return len(value) <= 32 and all(type(x) is int and -(2 ** 31) <= x < 2 ** 31 for x in value)
    if isinstance(value, str):
        return len(value) <= 64 and all(32 <= ord(ch) <= 126 for ch in value)
    return False


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
    if not isinstance(inputs, dict) or any(not valid_input_value(v) for v in inputs.values()):
        raise ValueError("inputs must map parameter names to bounded integers, int arrays, or ASCII strings")
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
    ret_type = target["type"]["qualType"].split("(")[0].strip()
    if ret_type not in ("int", "unsigned int", "unsigned", "void") or target.get("variadic"):
        raise ValueError("only functions returning int, unsigned int, or void are supported")
    param_nodes = [n for n in target.get("inner", []) if n["kind"] == "ParmVarDecl"]
    parameters = [identifier(n.get("name")) for n in param_nodes]
    param_types = {n.get("name"): n.get("type", {}).get("qualType", "int") for n in param_nodes}
    for name, ptype in param_types.items():
        if ptype not in (SUPPORTED_INTEGER_TYPES | SUPPORTED_POINTER_TYPES):
            raise ValueError(f"parameter {name} has unsupported type {ptype}")
    logical_input = dict(inputs)
    extra_keys = {"index"} if ret_type == "void" and "index" in inputs else set()
    if argument_order:
        if len(argument_order) != len(parameters) or len(set(argument_order)) != len(argument_order) or set(argument_order) != (set(inputs) - extra_keys):
            raise ValueError("argument_order must name each input key exactly once")
        remapped = {param: inputs[key] for param, key in zip(parameters, argument_order)}
        for k in extra_keys:
            remapped[k] = inputs[k]
        inputs = remapped
    if len(parameters) > 8 or (set(inputs) - extra_keys) != set(parameters):
        raise ValueError("input keys must match the function's named parameters (at most eight)")
    void_array_param = None
    for name in parameters:
        val = inputs[name]
        ptype = param_types[name]
        if ptype in ("unsigned int", "unsigned"):
            if type(val) is not int or not 0 <= val < (2 ** 32):
                raise ValueError(f"parameter {name} requires an unsigned 32-bit integer")
        elif ptype in SUPPORTED_INTEGER_TYPES:
            if type(val) is not int or not -(2 ** 31) <= val < (2 ** 31):
                raise ValueError(f"parameter {name} requires a signed 32-bit integer")
        elif ptype in ("const int *", "int *"):
            if not isinstance(val, list) or not all(type(x) is int and -(2 ** 31) <= x < (2 ** 31) for x in val):
                raise ValueError(f"parameter {name} requires a bounded list of signed 32-bit integers")
            if ptype == "int *" and void_array_param is None:
                void_array_param = name
        elif ptype in ("const char *", "char *"):
            if not isinstance(val, str):
                raise ValueError(f"parameter {name} requires an ASCII string")
    if ret_type == "void":
        idx = inputs.get("index")
        if void_array_param is None or type(idx) is not int or not 0 <= idx < len(inputs[void_array_param]):
            raise ValueError("void functions require a mutable int* parameter and a valid index")
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
        ntype = node.get("type", {}).get("qualType", "int")
        if kind == "VarDecl":
            if ntype not in SUPPORTED_INTEGER_TYPES:
                raise ValueError("only plain integer local variables are supported")
        elif kind != "FunctionDecl" and ntype not in (SUPPORTED_INTEGER_TYPES | SUPPORTED_POINTER_TYPES):
            raise ValueError("only plain integer and parameter pointer expressions are supported")
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
            if ret_type == "void":
                if len(children) != 0:
                    raise ValueError("void return must not have a value")
            else:
                if len(children) != 1:
                    raise ValueError("return must have an int value")
                wrap(children[0], "return", "return")
        elif kind in ("IfStmt", "WhileStmt", "DoStmt", "ForStmt"):
            condition = children[2] if kind == "ForStmt" else children[-1] if kind == "DoStmt" else children[0]
            if not condition.get("kind"):
                raise ValueError("loops must have an explicit condition")
            wrap(condition, "condition", kind)
        elif kind == "CompoundAssignOperator" or (kind == "BinaryOperator" and node.get("opcode") == "="):
            if ntype in SUPPORTED_INTEGER_TYPES:
                wrap(node, "assign", target_name(children[0], allow_subscript=True))
        elif kind == "UnaryOperator":
            operation = node["opcode"]
            if operation in ("++", "--"):
                operand_type = children[0].get("type", {}).get("qualType", "")
                if operand_type in ("int", "unsigned int", "unsigned"):
                    name = target_name(children[0])
                    number = site(node, "update", name)
                    start, end = span(node)
                    delta = 1 if operation == "++" else -1
                    replacements[start] = (end, f"aivm_trace_update({number}, &{name}, {delta}, {int(node.get('isPostfix', False))})".encode())
                elif operand_type not in SUPPORTED_POINTER_TYPES:
                    raise ValueError("unsupported increment target")
            elif operation == "*":
                operand_type = children[0].get("type", {}).get("qualType", "")
                if operand_type not in SUPPORTED_POINTER_TYPES:
                    raise ValueError("dereference requires a supported pointer parameter")
            elif operation not in ("+", "-", "!", "~"):
                raise ValueError(f"unsupported unary operator: {operation}")
        for child in children:
            visit(child)

    scalar_params = [n for n in param_nodes if param_types[n["name"]] in SUPPORTED_INTEGER_TYPES]
    parameter_sites = [site(n, "parameter", n["name"]) for n in scalar_params]
    visit(target)
    void_return_site = site(target, "return", "return") if ret_type == "void" else None
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
    setup_parts, arg_exprs = [], []
    for name in parameters:
        ptype = param_types[name]
        val = inputs[name]
        if ptype in ("const int *", "int *"):
            elems = ",".join(c_integer(x) for x in val) if val else "0"
            size = len(val) if val else 1
            setup_parts.append(f"int aivm_arg_{name}[{size}]={{{elems}}};")
            arg_exprs.append(f"aivm_arg_{name}")
        elif ptype in ("const char *", "char *"):
            setup_parts.append(f"char aivm_arg_{name}[]={c_string(val)};")
            arg_exprs.append(f"aivm_arg_{name}")
        else:
            arg_exprs.append(c_integer(val, ptype))
    setup = "".join(setup_parts)
    arguments = ",".join(arg_exprs)
    entry = "".join(f"aivm_trace_value({number},{c_integer(inputs[n['name']], param_types[n['name']])});" for number, n in zip(parameter_sites, scalar_params))
    if ret_type == "void":
        idx = inputs["index"]
        main = f'\nint main(void){{{setup}{function}({arguments});int value=aivm_arg_{void_array_param}[{idx}];printf("AIVM_RESULT %d\\n",value);return 0;}}\n'
        traced_main = f'\nint main(void){{{setup}{entry}{function}({arguments});int value=aivm_trace_value({void_return_site},aivm_arg_{void_array_param}[{idx}]);printf("AIVM_RESULT %d\\n",value);return 0;}}\n'
    else:
        main = f'\nint main(void){{{setup}int value=(int){function}({arguments});printf("AIVM_RESULT %d\\n",value);return 0;}}\n'
        traced_main = f'\nint main(void){{{setup}{entry}int value=(int){function}({arguments});printf("AIVM_RESULT %d\\n",value);return 0;}}\n'
    original = b"#include <stdio.h>\n" + source + main.encode()
    # helper รับ expression value เพียงครั้งเดียว; postfix update คืนค่าเดิมตาม C semantics
    helper = f'''#include <stdio.h>
#include <stdlib.h>
static unsigned aivm_trace_count;
static int aivm_trace_value_i(int site, int value){{
    if(aivm_trace_count++ >= {max_events}){{puts("AIVM_TRACE_TRUNCATED");fflush(stdout);_Exit(75);}}
    printf("AIVM_TRACE {{\\"site\\":%d,\\"value\\":%d}}\\n",site,value);
    return value;
}}
static unsigned aivm_trace_value_u(int site, unsigned value){{
    if(aivm_trace_count++ >= {max_events}){{puts("AIVM_TRACE_TRUNCATED");fflush(stdout);_Exit(75);}}
    printf("AIVM_TRACE {{\\"site\\":%d,\\"value\\":%u}}\\n",site,value);
    return value;
}}
#define aivm_trace_value(site, val) \\
    _Generic((val), \\
        unsigned int: aivm_trace_value_u, \\
        default: aivm_trace_value_i \\
    )((site), (val))
static int aivm_trace_update_i(int site, int *value, int delta, int postfix){{
    int previous=*value; *value+=delta;
    aivm_trace_value(site,*value);
    return postfix ? previous : *value;
}}
static unsigned aivm_trace_update_u(int site, unsigned *value, int delta, int postfix){{
    unsigned previous=*value; *value+=delta;
    aivm_trace_value(site,(int)*value);
    return postfix ? previous : *value;
}}
#define aivm_trace_update(site, ptr, delta, postfix) \\
    _Generic((ptr), \\
        int*: aivm_trace_update_i, \\
        unsigned int*: aivm_trace_update_u \\
    )((site), (ptr), (delta), (postfix))
'''
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
