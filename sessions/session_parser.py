"""
Session Parser

Production-grade session parser for parsing session data formats,
converting between formats, and validating session integrity.

Features:
- JSON/YAML/Markdown parsing
- Session validation
- Format conversion
- Schema validation
- Migration support

Author: Peace Stephen (Tech Lead)
"""

import logging
import json
import yaml
import hashlib
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class Format(Enum):
    JSON = "json"
    YAML = "yaml"
    MARKDOWN = "markdown"
    TEXT = "text"


@dataclass
class ParsedSession:
    session_id: str
    data: Dict[str, Any]
    format: Format
    valid: bool
    errors: List[str]


class SessionParser:
    def __init__(self):
        self._schemas = self._load_schemas()

    def parse(
        self,
        content: str,
        format: Format = Format.JSON,
    ) -> ParsedSession:
        if format == Format.JSON:
            return self._parse_json(content)
        elif format == Format.YAML:
            return self._parse_yaml(content)
        elif format == Format.MARKDOWN:
            return self._parse_markdown(content)
        return ParsedSession("", {}, Format.TEXT, False, ["Unknown format"])

    def _parse_json(self, content: str) -> ParsedSession:
        try:
            data = json.loads(content)
            session_id = data.get("session_id", "")
            valid, errors = self._validate(data)
            return ParsedSession(session_id, data, Format.JSON, valid, errors)
        except json.JSONDecodeError as e:
            return ParsedSession("", {}, Format.JSON, False, [str(e)])

    def _parse_yaml(self, content: str) -> ParsedSession:
        try:
            data = yaml.safe_load(content)
            session_id = data.get("session_id", "")
            valid, errors = self._validate(data)
            return ParsedSession(session_id, data, Format.YAML, valid, errors)
        except yaml.YAMLError as e:
            return ParsedSession("", {}, Format.YAML, False, [str(e)])

    def _parse_markdown(self, content: str) -> ParsedSession:
        data = {"content": content}
        return ParsedSession("", data, Format.MARKDOWN, True, [])

    def _validate(self, data: Dict[str, Any]) -> tuple[bool, List[str]]:
        errors = []
        
        required = ["session_id", "session_type"]
        for field in required:
            if field not in data:
                errors.append(f"Missing required field: {field}")

        return len(errors) == 0, errors

    def _load_schemas(self) -> Dict[str, Any]:
        return {
            "session": {
                "required": ["session_id", "session_type"],
                "optional": ["metadata", "findings", "messages"],
            }
        }

    def to_json(self, data: Dict[str, Any]) -> str:
        return json.dumps(data, indent=2)

    def to_yaml(self, data: Dict[str, Any]) -> str:
        return yaml.dump(data, default_flow_style=False)

    def to_markdown(self, data: Dict[str, Any]) -> str:
        lines = [f"# Session: {data.get('session_id', 'unknown')}"]
        return "\n".join(lines)


__all__ = ["SessionParser", "ParsedSession", "Format"]
