from fontTools.misc.cython import returns

from log_analyzer.reader import get_logs

logs = "network_traffic.log"


def get_out_ips(data):
    out_ips = [log[1] for log in data if not log[1].startswith(("10.", "192.168."))]
    return out_ips


def get_sensitive_ports(data):
    sensitive_ports = [log for log in data if int(log[3]) in [22, 33, 3389]]
    return sensitive_ports


def size_filter(data):
    filtered_data = [log for log in data if int(log[5]) > 5000]
    return filtered_data


def add_lable(data):
    for log in data:
        if int(log[5]) > 5000:
            log.append("LARGE")
        else:
            log.append("NORMAL")
    return data

def count_sendings(data):
    ips = [log[1] for log in data]

    counted_data = {ip: ips.count(ip) for ip in set(ips)}
    return counted_data

def port_protocol_dict(data):
    ports_protocol = {log[3]: log[4]  for log in data}
    return ports_protocol




def main():
    data = get_logs(logs)
    ips = count_sendings(data)
    ports_protocol =port_protocol_dict(data)

    print(ports_protocol)


if __name__ == "__main__":
    main()
