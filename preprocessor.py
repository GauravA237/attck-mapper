import re

def preprocess(log_line: str) -> str:
    line = log_line.lower().strip()
    line = re.sub(r'\s+', ' ', line)
    line = re.sub(r'[^\x20-\x7e]', '', line)
    return line

def load_log_file(filepath: str) -> list:
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()

    return [line.strip() for line in lines if line.strip()]


if __name__ == "__main__":
    logs = load_log_file("sample.log")
    print(f"Loaded {len(logs)} log lines\n")
    for line in logs:
        cleaned = preprocess(line)
        print(f"RAW: {line[:80]}")
        print(f"CLEAN: {cleaned[:80]}")
        print("----")