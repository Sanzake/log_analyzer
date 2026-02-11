from log_analyzer import config
from log_analyzer.analyzer import Analyzer, check_suspicions, suspicion_checks
from log_analyzer.reader import get_logs


def main():
    data = get_logs(config.LOG_FILE)
    analyzer = Analyzer(data)

    result = list(map(lambda x: check_suspicions(x, suspicion_checks), data))
    ans = list(filter(lambda x: len(x) > 0, result))
    print(ans)


if __name__ == "__main__":
    main()
