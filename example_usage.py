from client import AgenticApiPayloadFuzzingValidatorClient
import json, sys
sys.stdout.reconfigure(encoding='utf-8')

def main():
    client = AgenticApiPayloadFuzzingValidatorClient()
    print("=== AGENTIC API PAYLOAD FUZZING VALIDATOR ===")
    
    schema = {
        "customer_id": "string",
        "order_amount": "float",
        "quantity": "integer",
        "is_expedited": "boolean",
        "shipping_notes": "string"
    }
    
    res = client.generate_fuzz_vectors(schema)
    print(f"Target Schema Fields: {list(schema.keys())}")
    print(f"Generated {res['generated_vectors_count']} Fuzz Test Suites:")
    print()
    
    for i, vec in enumerate(res['fuzz_test_vectors'], 1):
        print(f"{i}. Suite: {vec['category']}")
        for k, v in vec['payload'].items():
            val_repr = str(v)[:40] + ("..." if len(str(v)) > 40 else "")
            print(f"   - {k}: {val_repr}")

if __name__ == "__main__":
    main()
