import sys, json
from client import AgenticApiPayloadFuzzingValidatorClient
sys.stdout.reconfigure(encoding='utf-8')

def handle_mcp():
    client = AgenticApiPayloadFuzzingValidatorClient()
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        print(json.dumps({"status": "ready", "skill": "genpark-agentic-api-payload-fuzzing-validator-skill"}))
        return
    req = json.loads(sys.stdin.read() or "{}")
    schema = req.get("schema", {"id": "string", "amount": "integer"})
    res = client.generate_fuzz_vectors(schema)
    print(json.dumps(res, indent=2))

if __name__ == "__main__":
    handle_mcp()
