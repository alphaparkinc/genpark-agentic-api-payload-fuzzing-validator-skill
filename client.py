import math, sys
sys.stdout.reconfigure(encoding='utf-8')

class AgenticApiPayloadFuzzingValidatorClient:
    """
    Autonomous API schema security and robustness fuzzer. Synthesizes combinatorial
    edge-case vectors (boundary integers, SQL injection tokens, Unicode RTL characters,
    excessively deep structures) to test schema resilience.
    """
    def __init__(self):
        self.boundary_integers = [0, -1, 1, 2147483647, -2147483648, 9223372036854775807, -9223372036854775808]
        self.boundary_floats = [0.0, -0.0, 1e-15, 1e308, -1e308]
        self.boundary_strings = [
            "",
            "A" * 1024,
            "\x00\x01\x02",
            "' OR '1'='1' --",
            "<script>alert(1)</script>",
            "{{7*7}}",
            "\u202Ereversed\u202C",
            "../../../../etc/passwd",
            "null",
            "true"
        ]

    def compute_shannon_entropy(self, payload_str):
        if not payload_str:
            return 0.0
        counts = {}
        for c in payload_str:
            counts[c] = counts.get(c, 0) + 1
        entropy = 0.0
        length = float(len(payload_str))
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return round(entropy, 3)

    def generate_fuzz_vectors(self, endpoint_schema):
        # endpoint_schema: {"field_name": "type"}
        fuzz_cases = []
        
        # Test Case 1: All Boundary Minima / Nulls
        case_nulls = {}
        for field, ftype in endpoint_schema.items():
            if ftype == "integer":
                case_nulls[field] = 0
            elif ftype == "string":
                case_nulls[field] = ""
            elif ftype == "float":
                case_nulls[field] = 0.0
            elif ftype == "boolean":
                case_nulls[field] = False
        fuzz_cases.append({"category": "BOUNDARY_MINIMA", "payload": case_nulls})

        # Test Case 2: Boundary Maxima / Overflow
        case_overflow = {}
        for field, ftype in endpoint_schema.items():
            if ftype == "integer":
                case_overflow[field] = 9223372036854775807
            elif ftype == "string":
                case_overflow[field] = "OVERFLOW_" * 128
            elif ftype == "float":
                case_overflow[field] = 1e308
            elif ftype == "boolean":
                case_overflow[field] = True
        fuzz_cases.append({"category": "BOUNDARY_MAXIMA", "payload": case_overflow})

        # Test Case 3: Injection & Escapes
        case_injection = {}
        for field, ftype in endpoint_schema.items():
            if ftype == "string":
                case_injection[field] = "' OR 1=1; DROP TABLE users; --"
            elif ftype == "integer":
                case_injection[field] = -1
            else:
                case_injection[field] = None
        fuzz_cases.append({"category": "SECURITY_INJECTION_PROBES", "payload": case_injection})

        # Test Case 4: Unicode & Control Characters
        case_unicode = {}
        for field, ftype in endpoint_schema.items():
            if ftype == "string":
                case_unicode[field] = "\u202E\u0000\uFEFFtest\x7F"
            else:
                case_unicode[field] = 1
        fuzz_cases.append({"category": "UNICODE_CONTROL_MUTATION", "payload": case_unicode})

        return {
            "status": "success",
            "schema_fields_count": len(endpoint_schema),
            "generated_vectors_count": len(fuzz_cases),
            "fuzz_test_vectors": fuzz_cases
        }
