import json
import csv
import os

def load_results(path="output/report.json"):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def export_csv(results, path="output/report.csv"):
    detections = results["detections"]
    if not detections:
        print("No detections to export.")
        return

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=detections[0].keys())
        writer.writeheader()
        writer.writerows(detections)

    print(f"CSV saved to {path}")

def export_navigator_layer(results, path="output/layer.json"):
    detections = results["detections"]

    # if same technique appears multiple times, keep highest confidence
    seen = {}
    for d in detections:
        tid = d["technique"]
        seen[tid] = max(seen.get(tid, 0), d["confidence"])

    layer = {
        "name": "SOC Detection Results",
        "versions": {
            "attack": "19",
            "navigator": "5.1.0",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Auto-generated layer from SOC detection pipeline",
        "techniques": [
            {
                "techniqueID": tid,
                "score": int(score * 100),
                "color": "",
                "comment": f"Confidence: {score}",
                "enabled": True
            }
            for tid, score in seen.items()
        ],
        "gradient": {
            "colors": ["#ffffff", "#ff6666"],
            "minValue": 0,
            "maxValue": 100
        },
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd"
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(layer, f, indent=2)

    print(f"Navigator layer saved to {path}")

def print_summary(results):
    print("=" * 60)
    print("EXPORT SUMMARY")
    print("=" * 60)
    print(f"Total detections:  {results['total_detections']}")
    print(f"Unique techniques: {results['unique_techniques']}")
    print(f"Unique tactics:    {results['unique_tactics']}")
    print(f"Tactics hit:       {', '.join(results['tactics_hit'])}")
    print()
    print("Techniques detected:")
    seen = set()
    for d in results["detections"]:
        if d["technique"] not in seen:
            seen.add(d["technique"])
            print(f"  {d['technique']} | {d['technique_name']} | {d['tactic']} | confidence: {d['confidence']}")

if __name__ == "__main__":
    os.makedirs("output", exist_ok=True)
    results = load_results()

    print_summary(results)
    print()
    export_csv(results)
    export_navigator_layer(results)

    print()
    print("All exports complete.")
    print("Upload output/layer.json to https://mitre-attack.github.io/attack-navigator")
    print("to see your detections as a heatmap on the full ATT&CK matrix.")