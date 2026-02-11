from log_analyzer import config
from log_analyzer.analyzer import Analyzer
from log_analyzer.reader import get_logs


def main():
    data = get_logs(config.LOG_FILE)
    analyzer = Analyzer(data)

    suspicions = analyzer.identify_suspicions()
    for i in suspicions:
        print(i, suspicions[i])


if __name__ == "__main__":
    main()
