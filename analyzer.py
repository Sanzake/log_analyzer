from collections import Counter
from datetime import datetime

from log_analyzer import config


def is_external(ip):
    return not ip.startswith(config.INTERNAL)


class Analyzer:
    def __init__(self, logs):
        self.logs = logs

    def get_external(self):
        return [log for log in self.logs if is_external(log.sender)]

    def get_sensitive_ports(self):
        sensitive_ports = [log for log in self.logs if log.port in config.SENSITIVE_PORTS]
        return sensitive_ports

    def size_filter(self):
        filtered_data = [log for log in self.logs if log.size > 5000]
        return filtered_data

    def add_label(self):
        for log in self.logs:
            if log.size > 5000:
                log.label = "LARGE"
            else:
                log.label = "NORMAL"
        return self.logs

    def count_sendings(self):
        return Counter(log.sender for log in self.logs)

        # counted_data = {}
        #
        # for log in self.logs:
        #     counted_data[log.sender] = counted_data.get(log.sender, 0) + 1
        #
        #
        # counted_data = {log.sender: 0 for log in self.logs}
        #
        # for log in self.logs:
        #     counted_data[log.sender] += 1
        #
        # return counted_data

    def port_protocol_dict(self):
        ports_protocol = {log.port: log.protocol for log in self.logs}
        return ports_protocol

    def get_night_activity(self):
        night_activity = []
        for log in self.logs:
            dt = datetime.strptime(log.date, "%Y-%m-%d %H:%M:%S")
            if 0 <= dt.hour < 7:
                night_activity.append(log)
        return night_activity

    def identify_suspicions(self):
        identified = {}

        for log in self.logs:
            dt = datetime.strptime(log.date, "%Y-%m-%d %H:%M:%S")

            if is_external(log.sender):
                identified.setdefault(log.sender, set()).add("EXTERNAL_IP")
            if log.port in config.SENSITIVE_PORTS:
                identified.setdefault(log.sender, set()).add("SENSITIVE_PORT")
            if log.size > 5000:
                identified.setdefault(log.sender, set()).add("LARGE_PACKET")
            if 0 <= dt.hour < 7:
                identified.setdefault(log.sender, set()).add("NIGHT_ACTIVITY")

        return identified

    def filter_by_2_suspicions(self):
        suspicions = self.identify_suspicions()

        suspicions_filtered = {ip: values for ip, values in suspicions.items() if len(values) > 1}
        return suspicions_filtered

    def get_hours(self):
        return list(map(lambda x: datetime.strptime(x.date, "%Y-%m-%d %H:%M:%S").hour, self.logs))

    def get_kb_sizes(self):
        return list(map(lambda x: x.size / 1024, self.logs))
