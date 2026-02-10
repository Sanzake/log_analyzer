import csv
from pathlib import Path


def get_logs(path):
    path = Path(path)
    if not path.exists():
        print("Error: FileDoesntExist")
        return
    with open(path, "r", encoding="utf-8") as f:
        data = csv.reader(f)
        logs = list(data)
        return logs