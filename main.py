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

def get_sensitive_ports(data):
    sensitive_ports = [log for log in data if int(log[3]) in [22,33,3389]]
    return sensitive_ports


def main():
    data = get_logs(logs)
    out_ips = get_out_ips(data)
    sensitive_ports = get_sensitive_ports(data)

if __name__ == "__main__":
    main()
