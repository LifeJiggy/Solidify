"""
Solidify File Injector
Dynamic file injection for context enrichment

Author: Peace Stephen (Tech Lead)
Description: Inject files into LLM context
"""

import os
import re
import json
import logging
from typing import Dict, Any, List, Optional, Set, Callable
from dataclasses import dataclass, field
from pathlib import Path
from enum import Enum

logger = logging.getLogger(__name__)


class FileType(Enum):
    SOLIDITY = ".sol"
    JAVASCRIPT = ".js"
    TYPESCRIPT = ".ts"
    PYTHON = ".py"
    MARKDOWN = ".md"
    JSON = ".json"
    YAML = ".yaml"
    TXT = ".txt"


@dataclass
class FileContext:
    path: str
    content: str
    file_type: FileType
    size: int
    lines: int
    language: str


@dataclass
class InjectionResult:
    success: bool
    files_injected: int
    total_size: int
    content: str
    errors: List[str] = field(default_factory=list)


class FileScanner:
    """Scan files for injection"""
    
    def __init__(self, extensions: Optional[Set[str]] = None):
        self.extensions = extensions or {".sol", ".js", ".ts", ".py"}
        self._exclude_patterns = {
            "^node_modules",
            "^cache",
            "^dist",
            "^build",
            "\.git",
            "\.test\.",
            "\.mock\.",
            "bridge\.sol$",
            "mock\.sol$"
        }
    
    def scan_directory(
        self,
        directory: str,
        recursive: bool = True
    ) -> List[str]:
        files = []
        
        try:
            if recursive:
                for root, dirs, filenames in os.walk(directory):
                    dirs[:] = [d for d in dirs if not self._should_exclude(d)]
                    
                    for filename in filenames:
                        filepath = os.path.join(root, filename)
                        if self._should_include(filename):
                            files.append(filepath)
            else:
                files = [
                    os.path.join(directory, f)
                    for f in os.listdir(directory)
                    if os.path.isfile(os.path.join(directory, f))
                    and self._should_include(f)
                ]
        except Exception as e:
            logger.error(f"Error scanning {directory}: {str(e)}")
        
        return files
    
    def _should_exclude(self, name: str) -> bool:
        for pattern in self._exclude_patterns:
            if re.match(pattern, name):
                return True
        return False
    
    def _should_include(self, filename: str) -> bool:
        ext = os.path.splitext(filename)[1]
        return ext in self.extensions


class FileReader:
    """Read file contents"""
    
    def __init__(self, max_size: int = 100000):
        self.max_size = max_size
    
    def read(self, filepath: str) -> Optional[str]:
        try:
            if os.path.getsize(filepath) > self.max_size:
                logger.warning(f"File too large: {filepath}")
                return None
            
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading {filepath}: {str(e)}")
            return None
    
    def read_lines(self, filepath: str, limit: Optional[int] = None) -> List[str]:
        content = self.read(filepath)
        if not content:
            return []
        
        lines = content.split('\n')
        return lines[:limit] if limit else lines


class FileFormatter:
    """Format files for injection"""
    
    def __init__(self):
        self.max_file_size = 50000
    
    def format_solidity(self, content: str, filename: str) -> str:
        return f"""// File: {filename}
// SPDX-License-Identifier: MIT
{content}"""
    
    def format_javascript(self, content: str, filename: str) -> str:
        return f"""// File: {filename}\n{content}"""
    
    def format_python(self, content: str, filename: str) -> str:
        return f'''# File: {filename}
{content}'''
    
    def format_generic(self, content: str, filename: str) -> str:
        return f"""=== {filename} ===
{content}
=== End {filename} ==="""


class FileSelector:
    """Select files based on criteria"""
    
    def __init__(self):
        self._criteria: List[Callable] = []
    
    def add_criterion(self, criterion: Callable) -> None:
        self._criteria.append(criterion)
    
    def select(
        self,
        files: List[str],
        max_files: int = 10,
        max_total_size: int = 100000
    ) -> List[str]:
        selected = []
        total_size = 0
        
        for filepath in files:
            try:
                size = os.path.getsize(filepath)
                
                if total_size + size > max_total_size:
                    continue
                
                if len(selected) >= max_files:
                    break
                
                passes = all(c(filepath) for c in self._criteria)
                if passes or not self._criteria:
                    selected.append(filepath)
                    total_size += size
            except Exception:
                pass
        
        return selected


class FileInjector:
    """Main file injector"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.scanner = FileScanner()
        self.reader = FileReader()
        self.formatter = FileFormatter()
        self.selector = FileSelector()
        self._setup_default_criteria()
        
        logger.info("✅ File Injector initialized")
    
    def _setup_default_criteria(self):
        self.selector.add_criterion(lambda f: os.path.getsize(f) < 50000)
    
    def inject_files(
        self,
        directory: str,
        pattern: Optional[str] = None,
        max_files: int = 10
    ) -> InjectionResult:
        result = InjectionResult(success=False, files_injected=0, total_size=0, content="")
        errors = []
        
        try:
            files = self.scanner.scan_directory(directory)
            
            if pattern:
                files = [f for f in files if pattern in f]
            
            files = self.selector.select(files, max_files=max_files)
            
            contents = []
            total_size = 0
            
            for filepath in files:
                content = self.reader.read(filepath)
                if content:
                    filename = os.path.basename(filepath)
                    ext = os.path.splitext(filename)[1]
                    
                    if ext == ".sol":
                        formatted = self.formatter.format_solidity(content, filename)
                    elif ext in [".js", ".ts"]:
                        formatted = self.formatter.format_javascript(content, filename)
                    elif ext == ".py":
                        formatted = self.formatter.format_python(content, filename)
                    else:
                        formatted = self.formatter.format_generic(content, filename)
                    
                    contents.append(formatted)
                    total_size += len(content)
                else:
                    errors.append(f"Could not read: {filepath}")
            
            result.success = len(contents) > 0
            result.files_injected = len(contents)
            result.total_size = total_size
            result.content = "\n\n".join(contents)
            result.errors = errors
            
        except Exception as e:
            result.errors.append(str(e))
            logger.error(f"Injection error: {str(e)}")
        
        return result
    
    def inject_file(self, filepath: str) -> Optional[str]:
        content = self.reader.read(filepath)
        if not content:
            return None
        
        filename = os.path.basename(filepath)
        ext = os.path.splitext(filename)[1]
        
        if ext == ".sol":
            return self.formatter.format_solidity(content, filename)
        elif ext in [".js", ".ts"]:
            return self.formatter.format_javascript(content, filename)
        elif ext == ".py":
            return self.formatter.format_python(content, filename)
        
        return self.formatter.format_generic(content, filename)
    
    def inject_pattern(
        self,
        directory: str,
        pattern: str
    ) -> InjectionResult:
        return self.inject_files(directory, pattern=pattern)


class ContextEnricher:
    """Enrich context with files"""
    
    def __init__(self, injector: Optional[FileInjector] = None):
        self.injector = injector or FileInjector()
        self._injected_content: List[str] = []
    
    def enrich(
        self,
        directory: str,
        pattern: Optional[str] = None
    ) -> str:
        result = self.injector.inject_files(directory, pattern=pattern)
        
        if result.success:
            self._injected_content.append(result.content)
        
        return result.content
    
    def get_injected(self) -> List[str]:
        return self._injected_content.copy()
    
    def clear(self) -> None:
        self._injected_content.clear()
    
    def build_context(
        self,
        prompt: str,
        directory: str,
        pattern: Optional[str] = None
    ) -> str:
        files_content = self.enrich(directory, pattern)
        
        if files_content:
            return f"""Context Files:
{files_content}

User Request:
{prompt}"""
        
        return prompt


class DynamicFileInjector:
    """Dynamic file injection based on content analysis"""
    
    def __init__(self):
        self.injector = FileInjector()
        self.detectors = {
            "solidity": lambda c: "pragma solidity" in c,
            "javascript": lambda c: "const " in c or "function " in c,
            "python": lambda c: "def " in c or "import " in c,
            "defi": lambda c: "uniswap" in c.lower() or "aave" in c.lower()
        }
    
    def detect_language(self, content: str) -> Optional[str]:
        for lang, detector in self.detectors.items():
            if detector(content):
                return lang
        return None
    
    def auto_inject(
        self,
        directory: str,
        target_language: Optional[str] = None
    ) -> InjectionResult:
        files = self.injector.scanner.scan_directory(directory)
        
        if target_language:
            detector = self.detectors.get(target_language)
            if detector:
                filtered = []
                for f in files:
                    content = self.injector.reader.read(f)
                    if content and detector(content):
                        filtered.append(f)
                files = filtered
        
        return self.injector.inject_files(directory)


class FileInjectionManager:
    """Manage file injections"""
    
    def __init__(self):
        self.injectors: Dict[str, FileInjector] = {}
        self._default: Optional[FileInjector] = None
    
    def create_injector(
        self,
        name: str,
        config: Optional[Dict[str, Any]] = None
    ) -> FileInjector:
        injector = FileInjector(config)
        self.injectors[name] = injector
        
        if not self._default:
            self._default = name
        
        return injector
    
    def get_injector(self, name: Optional[str] = None) -> Optional[FileInjector]:
        key = name or self._default
        return self.injectors.get(key)
    
    def inject(
        self,
        name: Optional[str],
        directory: str,
        pattern: Optional[str] = None
    ) -> InjectionResult:
        injector = self.get_injector(name)
        if not injector:
            return InjectionResult(success=False, files_injected=0, total_size=0, content="")
        
        return injector.inject_files(directory, pattern=pattern)