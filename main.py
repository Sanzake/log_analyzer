from log_analyzer import config
from log_analyzer.analyzer import Analyzer
from log_analyzer.reader import get_logs


def main():
    data = get_logs(config.LOG_FILE)
    analyzer = Analyzer(data)


    print(analyzer.get_kb_sizes())


if __name__ == "__main__":
    main()
