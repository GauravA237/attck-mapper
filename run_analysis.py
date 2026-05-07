from detector import load_rules, analyze_log_file
import json

if __name__ == "__main__":
    rules = load_rules()
    results = analyze_log_file("sample.log", rules)

    # print summary
    print("=" * 60)
    print("DETECTION SUMMARY")
    print("=" * 60)
    print(f"Lines analyzed:     {results['total_lines_analyzed']}")
    print(f"Total detections:   {results['total_detections']}")
    print(f"Unique techniques:  {results['unique_techniques']}")
    print(f"Unique tactics:     {results['unique_tactics']}")
    print(f"Tactics covered:    {', '.join(results['tactics_hit'])}")
    print()

    # print each detection
    print("DETECTIONS")
    print("=" * 60)
    for d in results["detections"]:
        print(f"[{d['rule_id']}] {d['technique']} | {d['tactic']} | confidence: {d['confidence']}")
        print(f"  Technique : {d['technique_name']}")
        print(f"  Detail    : {d['description']}")
        print(f"  Log line  : {d['matched_line'][:70]}")
        print()

    # save to output/report.json
    import os
    os.makedirs("output", exist_ok=True)
    with open("output/report.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    print("=" * 60)
    print("Report saved to output/report.json")