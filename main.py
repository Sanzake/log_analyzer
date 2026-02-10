import csv

logs = "network_traffic.log"


def get_logs(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        data = list(reader)
        return data


def main():
    get_logs(logs)


if __name__ == "__main__":
    main()
