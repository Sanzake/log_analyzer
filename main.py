import csv

logs = "network_traffic.log"


def get_logs(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        data = list(reader)
        return data

def get_out_ips(data):
    out_ips = [log[1] for log in data if not log[1].startswith(("10.", "192.168."))]
    return out_ips


def main():
    data = get_logs(logs)
    for i in get_out_ips(data):
        print(i)


if __name__ == "__main__":
    main()
