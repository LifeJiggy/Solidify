"""
Command Parser Module
Parses CLI command arguments

Author: Solidify Security Team
"""

import argparse
import shlex
from typing import Dict, List, Optional, Any


class CommandParser:
    def __init__(self):
        self._parsers: Dict[str, argparse.ArgumentParser] = {}

    def add_parser(self, name: str, parser: argparse.ArgumentParser) -> None:
        self._parsers[name] = parser

    def parse(self, args: str) -> Dict[str, Any]:
        try:
            tokens = shlex.split(args)
            parsed = self._parsers.get(tokens[0])
            if parsed:
                return vars(parsed.parse_args(tokens[1:]))
            return {}
        except:
            return {}

    def parse_list(self, args: str) -> List[str]:
        try:
            return shlex.split(args)
        except:
            return []


class AuditParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("action", choices=["create", "list", "get", "run"])
        self.parser.add_argument("--title")
        self.parser.add_argument("--description")
        self.parser.add_argument("--network")
        self.parser.add_argument("--audit-id")


class ScanParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("action", choices=["quick", "full"])
        self.parser.add_argument("--address", required=True)
        self.parser.add_argument("--network", default="ethereum")


class ReportParser:
    def __init__(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("action", choices=["generate", "list", "download"])
        self.parser.add_argument("--audit-id", required=True)
        self.parser.add_argument("--format", choices=["json", "html", "pdf", "markdown"])


def parse_args(args: str) -> Dict[str, Any]:
    parser = CommandParser()
    return parser.parse(args)


def main():
    import sys
    result = parse_args(" ".join(sys.argv[1:]))
    print(result)


if __name__ == "__main__":
    main()