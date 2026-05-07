import json
import re
from preprocessor import preprocess, load_log_file

def load_rules(path="rules/patterns.json"):
    with open(path, "r") as f:
        return json.load(f)

if __name__ == "__main__":
    rules = load_rules()
    logs = load_log_file("sample.log")

    print(f"Loaded {len(rules)} rules and {len(logs)} log lines\n")
    print("=" * 60)

    for log in logs:
        cleaned = preprocess(log)
        matches = []
        for rule in rules:
            if re.search(rule["pattern"], cleaned, re.IGNORECASE):
                matches.append(rule)

        if matches:
            print(f"LOG: {log[:70]}")
            for m in matches:
                print(f"  [{m['id']}] {m['technique']} | {m['tactic']} | confidence: {m['confidence']}")
                print(f"       {m['description']}")
            print()