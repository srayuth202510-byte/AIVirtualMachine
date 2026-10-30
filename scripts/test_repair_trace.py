"""Check source instrumentation boundaries and C semantics before native collection."""
import shutil
import subprocess
import unittest
from unittest.mock import patch

import repair_trace as trace
import release_evidence as evidence


@unittest.skipUnless(shutil.which("clang"), "native C trace preparation requires clang")
class InstrumentationTests(unittest.TestCase):
    def prepare(self, source, name="power", inputs=None):
        return trace.prepare(source.encode(), name, inputs if inputs is not None else {"b": -3, "e": 1})

    def check_c(self, source):
        result = subprocess.run([shutil.which("clang"), "-x", "c", "-std=c11", "-fsyntax-only", "-"],
                                input=source, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_power_sites_come_from_ast_and_generated_units_compile(self):
        source = "int power(int b,int e){if(e==0)return 1;int r=b;for(int i=0;i<e;i++)r*=b;return r;}"
        bundle, original, traced = self.prepare(source)
        self.assertEqual(bundle["source_sha256"], trace.digest(source.encode()))
        self.assertIn(("initialize", "r"), [(s["kind"], s["name"]) for s in bundle["sites"]])
        self.assertIn(("assign", "r"), [(s["kind"], s["name"]) for s in bundle["sites"]])
        self.assertIn(("update", "i"), [(s["kind"], s["name"]) for s in bundle["sites"]])
        self.check_c(original)
        self.check_c(traced)

    def test_nested_wrappers_and_postfix_values_compile(self):
        _, original, traced = self.prepare(
            "int ticks(int n){int old=n++;int a=0;while(n<5){a+=(n++);}return old+a;}",
            "ticks", {"n": 3})
        self.assertIn(b"&n, 1, 1)", traced)
        self.check_c(original)
        self.check_c(traced)

    def test_do_if_else_and_short_circuit_compile(self):
        _, _, traced = self.prepare(
            "int choose(int n){int a=0;do{if(n>0 && ++a<3)n--;else break;}while(n>0);return (a=2);}",
            "choose", {"n": 3})
        self.check_c(traced)

    def test_unsigned_parameters_and_c_style_casts_compile(self):
        source = "int popcount(unsigned x){int n=0;while(x){n+=(int)(x&1u);x>>=1;}return n;}"
        bundle, original, traced = trace.prepare(source.encode(), "popcount", {"x": 7})
        self.assertEqual(bundle["function"], "popcount")
        self.check_c(original)
        self.check_c(traced)
        with self.assertRaises(ValueError):
            trace.prepare(source.encode(), "popcount", {"x": -1})
        with self.assertRaises(ValueError):
            trace.prepare(source.encode(), "popcount", {"x": 2 ** 32})

    def test_array_string_and_void_parameters_compile(self):
        arr_src = "int positive_count(const int*a,int n){int c=0;for(int i=0;i<n;i++)c+=a[i]>0;return c;}"
        _, orig, traced = trace.prepare(arr_src.encode(), None, {"a": [0, -1, 2], "n": 3})
        self.check_c(orig)
        self.check_c(traced)
        str_src = "int string_equal(const char*a,const char*b){while(*a&&*b){if(*a++!=*b++)return 0;}return *a==*b;}"
        _, orig, traced = trace.prepare(str_src.encode(), None, {"a": "a", "b": "ab"})
        self.check_c(orig)
        self.check_c(traced)
        void_src = "void reverse_array(int*a,int n){for(int i=0;i<n/2;i++){int t=a[i];a[i]=a[n-i-1];a[n-i-1]=t;}}"
        _, orig, traced = trace.prepare(void_src.encode(), None, {"a": [1, 2, 3], "n": 2, "index": 0})
        self.check_c(orig)
        self.check_c(traced)

    def test_input_keys_types_and_ranges_are_checked(self):
        for inputs in ({"b": -3}, {"b": True, "e": 1}, {"b": 2 ** 31, "e": 1}, {"b": "system()", "e": 1}):
            with self.subTest(inputs=inputs), self.assertRaises(ValueError):
                self.prepare("int power(int b,int e){return b;}", inputs=inputs)

    def test_worker_auto_detection_and_explicit_argument_mapping(self):
        source=b"int renamed(int base,int exponent){int r=base;for(int n=0;n<exponent;n++)r*=base;return r;}"
        bundle,_,unit=trace.prepare(source,None,{"b":-3,"e":1},argument_order=["b","e"])
        self.assertEqual(bundle["function"],"renamed")
        self.assertEqual(bundle["input"],{"base":-3,"exponent":1})
        self.assertEqual(bundle["logical_input"],{"b":-3,"e":1})
        self.check_c(unit)
        with self.assertRaises(ValueError):
            trace.prepare(source,None,{"b":-3,"e":1})

    def test_unsupported_constructs_and_reserved_symbols_are_rejected(self):
        sources = [
            "int global;int power(int b,int e){return global;}",
            "#include <stdlib.h>\nint power(int b,int e){return b;}",
            "int power(int b,int e){return power(b,e);}",
            "int power(int b,int e){int a[2]={1,2};return a[0];}",
            "int power(int b,int e){static int n=0;return n++;}",
            "int power(int b,int e){volatile int n=0;return n;}",
            "int power(int b,int e){int n;return n;}",
            "int power(int b,int e){for(;;){}return b;}",
            "int power(int b,int e){int aivm_trace_value=1;return b;}",
            "int power(int b,int e){return b;} int other(void){return 0;}",
            "int power(int b,int e){int *n=&b;return *n;}",
        ]
        for source in sources:
            with self.subTest(source=source), self.assertRaises(ValueError):
                self.prepare(source)

    def test_c_integer_min_and_name_injection(self):
        _, original, _ = self.prepare("int identity(int n){return n;}", "identity", {"n": -(2 ** 31)})
        self.assertIn(b"(-2147483647 - 1)", original)
        self.check_c(original)
        for name in ("main", "identity();system(1)", "aivm_trace_identity"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.prepare("int identity(int n){return n;}", name, {"n": 1})


class ContextTests(unittest.TestCase):
    def test_render_describes_observations_without_claiming_repair_success(self):
        rendered = trace.render({"function": "power", "input": {"b": -3, "e": 1},
                                 "source_sha256": "ab", "actual": 9,
                                 "events": [{"line": 1, "kind": "assign", "name": "r", "value": 9}]})
        self.assertIn("assign r = 9", rendered)
        self.assertIn("Actual returned value: 9", rendered)
        self.assertNotIn("tests passed", rendered)


class MeasurementTests(unittest.TestCase):
    def fixture(self, traced_value=9, event=None, extra=""):
        bundle = {"sites": [{"id": 1, "kind": "return", "name": "return", "line": 1}],
                  "max_events": 4, "original_sha256": "original", "traced_sha256": "traced",
                  "source_sha256": "source", "function": "f", "input": {"n": 3}}
        measurement = {"kind": "operator_trace_measurement_not_repair"}
        records = {}
        for label, value in (("original", 9), ("traced", traced_value)):
            output = f"exit status: 0\nAIVM_RESULT {value}\n"
            if label == "traced":
                output += "AIVM_TRACE " + (event or '{"site":1,"value":9}') + "\n" + extra
            checks = [{"ok": True}, {"ok": True}, {"ok": True, "output": output}]
            snapshot = {"task_id": label, "label": label, "source_sha256": label,
                        "checks_sha256": trace.digest(evidence.canonical(checks)), "verification_audit_id": "receipt"}
            records[label] = {"action": "native-trace-observation", "rule_matched": "native-output-snapshot",
                              "result": evidence.canonical(snapshot).decode()}
            measurement[label] = {"task_contract": {"task_id": label}, "outcome": {"verification": "passed"},
                                  "verification": {"audit_id": "receipt"}, "checks": checks,
                                  "snapshot": dict(snapshot, audit_id=label)}
        return bundle, measurement, records

    def validate(self, fixture):
        bundle, measurement, records = fixture
        # แยกทดสอบ stdout binding; hash-chain/outcome ใช้ตัวตรวจจริงใน native integration run
        with patch.object(evidence, "audit_records", return_value=records), patch.object(evidence, "valid_outcome", return_value=True):
            return trace.validate_measurements(bundle, measurement, {"original": "a", "traced": "b"})

    def test_observed_values_are_bound_to_audited_output(self):
        result = self.validate(self.fixture())
        self.assertEqual(result["actual"], 9)
        self.assertFalse(result["repair_verified"])

    def test_edited_stdout_is_rejected(self):
        fixture = self.fixture()
        fixture[1]["traced"]["checks"][-1]["output"] = "AIVM_RESULT 9\nAIVM_TRACE {\"site\":1,\"value\":9}\n"
        with self.assertRaisesRegex(ValueError, "snapshot"):
            self.validate(fixture)

    def test_different_result_truncation_and_invalid_site_are_rejected(self):
        for fixture in (self.fixture(traced_value=8), self.fixture(extra="AIVM_TRACE_TRUNCATED\n"),
                        self.fixture(event='{"site":2,"value":9}'), self.fixture(event='{"site":true,"value":9}')):
            with self.subTest(fixture=fixture), self.assertRaises(ValueError):
                self.validate(fixture)


if __name__ == "__main__":
    unittest.main()
