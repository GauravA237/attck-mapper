import re
import json
from preprocessor import preprocess

def load_rules(path="rules/patterns.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def detect(log_line: str, rules: list) -> list:
    cleaned = preprocess(log_line)
    hits = []
    for rule in rules:
        if re.search(rule["pattern"], cleaned, re.IGNORECASE):
            hits.append({
                "rule_id":        rule["id"],
                "technique":      rule["technique"],
                "technique_name": rule["technique_name"],
                "tactic":         rule["tactic"],
                "confidence":     rule["confidence"],
                "description":    rule["description"],
                "matched_line":   log_line.strip()
            })
    return hits

def analyze_log_file(filepath: str, rules: list) -> dict:
    from preprocessor import load_log_file
    lines = load_log_file(filepath)

    all_detections = []
    for line in lines:
        hits = detect(line, rules)
        all_detections.extend(hits)

    tactics_hit = list(set(d["tactic"] for d in all_detections))
    techniques_hit = list(set(d["technique"] for d in all_detections))

    return {
        "total_lines_analyzed": len(lines),
        "total_detections":     len(all_detections),
        "unique_techniques":    len(techniques_hit),
        "unique_tactics":       len(tactics_hit),
        "tactics_hit":          tactics_hit,
        "techniques_hit":       techniques_hit,
        "detections":           all_detections
    }