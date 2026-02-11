import csv
from pathlib import Path


class Log:
    def __init__(self, date, sender, receiver, port, protocol, size, label=None):
        self.date = date
        self.sender = sender
        self.receiver = receiver
        self.port = port
        self.protocol = protocol
        self.size = size
        self.label = label

    def __repr__(self):
        return f"{self.sender}, {self.receiver}, {self.port}, {self.protocol}, {self.size}, {self.label}"


def get_logs(path):
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError("File not found!")

    logs = []
    with open(path, "r", encoding="utf-8") as f:
        for row in csv.reader(f):
            logs.append(Log(
                date=row[0],
                sender=row[1],
                receiver=row[2],
                port=int(row[3]),
                protocol=row[4],
                size=int(row[5])
            ))
        return logs
