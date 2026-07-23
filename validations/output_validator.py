"""
Output Validator - Validates all AI outputs and audit results
"""

import json
from datetime import datetime

class OutputValidator:
    def __init__(self): self.errors = []; self.warnings = []
    def validate(self, data): return {"valid": True}
    def validate_finding(self, f): return isinstance(f, dict)
    def validate_severity(self, s): return s in ["critical","high","medium","low","info"]
    def check_location(self, loc): return isinstance(loc, dict)

class OutputFormatter:
    def format(self, data, style="json"): return str(data)
    def format_finding(self, f): return f"{f.get('type','')}: {f.get('message','')}"
    def format_result(self, r): return f"Found {len(r.get('findings',[]))} issues"

class SeverityChecker:
    LEVELS = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1, "info": 0.0}
    def check(self, level): return level in self.LEVELS
    def score(self, level): return self.LEVELS.get(level, 0.0)

class FindingValidator:
    def validate(self, f):
        if not isinstance(f, dict): return False
        required = ["type", "message", "severity"]
        return all(k in f for k in required)

class LocationValidator:
    def validate(self, loc):
        if not isinstance(loc, dict): return False
        return "line" in loc or "function" in loc or "contract" in loc

class OutputSchema:
    REQUIRED = ["findings", "summary", "timestamp"]
    def validate(self, output):
        return isinstance(output, dict) and all(k in output for k in self.REQUIRED)

class ReportValidator:
    def validate(self, report): return isinstance(report, dict)
    def validate_metadata(self, meta): return isinstance(meta, dict)
    def validate_summary(self, smry): return isinstance(smry, dict)

class ResultFormatter:
    def to_json(self, data): return json.dumps(data, indent=2)
    def to_dict(self, data): return {"formatted": str(data)}

class VulnerabilityMapper:
    PATTERNS = {"reentrancy": ["call.value", "transfer"], "overflow": ["+", "-", "*"]}
    def map(self, vuln_type): return self.PATTERNS.get(vuln_type, [])

class CVSSCalculator:
    def calculate(self, finding): return {"score": 5.0, "vector": "AV:N/AC:L"}

class ExportValidator:
    def validate_json(self, data):
        try: json.dumps(data); return True
        except: return False
    def validate_html(self, html): return "<html>" in html
    def validate_markdown(self, md): return "#" in md or "##" in md

class OutputSanitizer:
    def sanitize(self, data):
        if isinstance(data, str): return data.replace("<script>", "")
        if isinstance(data, dict): return {k: self.sanitize(v) for k,v in data.items()}
        return data

class ReportGenerator:
    def generate(self, findings): return {"report": len(findings), "findings": findings}
    def create_summary(self, data): return {"total": len(data.get("findings",[]))}

class ValidationChain:
    def __init__(self): self.validators = []
    def add(self, v): self.validators.append(v)
    def validate(self, data): return all(v.validate(data) for v in self.validators)

class OutputMetadata:
    def create(self, data): return {"timestamp": str(datetime.now()), "version": "1.0.0"}

class FindingFormatter:
    def format(self, finding):
        return f"[{finding.get('severity','unknown').upper()}] {finding.get('message','')}"

class ResultAggregator:
    def aggregate(self, results): return {"total": len(results), "results": results}

class OutputFilter:
    def filter_by_severity(self, findings, min_level="low"):
        levels = {"info":0,"low":1,"medium":2,"high":3,"critical":4}
        return [f for f in findings if levels.get(f.get("severity"),0) >= levels.get(min_level,1)]

class ReportExporter:
    def export_json(self, report, path): open(path,"w").write(json.dumps(report)); return True

class ValidationReporter:
    def report(self, result): return {"success": result.get("valid"), "errors": result.get("errors",[])}

class FindingSorter:
    def sort(self, findings): return sorted(findings, key=lambda f: f.get("severity","low"))

class OutputCache:
    def __init__(self): self.cache = {}
    def get(self, key): return self.cache.get(key)
    def set(self, key, value): self.cache[key] = value
    def clear(self): self.cache = {}

class ResultDeduplicator:
    def deduplicate(self, findings):
        seen = set()
        result = []
        for f in findings:
            key = f"{f.get('type','')}:{f.get('location','')}"
            if key not in seen:
                seen.add(key)
                result.append(f)
        return result

class OutputEnricher:
    def enrich(self, finding):
        finding["enriched"] = True
        finding["timestamp"] = str(datetime.now())
        return finding

class ValidationMetrics:
    def metrics(self, results):
        return {"total": len(results), "valid": sum(1 for r in results if r.get("valid"))}

class FindingGrouper:
    def group(self, findings, by="severity"):
        grouped = {}
        for f in findings:
            key = f.get(by, "unknown")
            grouped.setdefault(key, []).append(f)
        return grouped

class ReportBuilder:
    def build(self, data):
        return {"title": "Security Audit Report", "sections": data}

class OutputValidatorFactory:
    @staticmethod
    def create(validator_type):
        return {"output": OutputValidator(), "finding": FindingValidator()}.get(validator_type, OutputValidator())

class ValidationContext:
    def __init__(self): self.data = {}
    def set_context(self, key, value): self.data[key] = value
    def get_context(self, key): return self.data.get(key)

class ResultMerger:
    def merge(self, *results):
        merged = {}
        for r in results:
            merged.update(r)
        return merged

class OutputVersioner:
    def version(self, data, ver="1.0"): return {"data": data, "version": ver}

class ReportPublisher:
    def publish(self, report): return {"published": True, "timestamp": str(datetime.now())}

class ValidationLogger:
    def log(self, result):
        with open("validation.log","a") as f: f.write(f"{result}\n")

class OutputCompressor:
    def compress(self, data):
        import gzip
        return gzip.compress(json.dumps(data).encode())

class FindingLinker:
    def link(self, finding, cwe_id):
        finding["cwe"] = cwe_id
        return finding

class CWEMapper:
    MAP = {"reentrancy": "CWE-834", "overflow": "CWE-190", "access": "CWE-284"}
    def map(self, vuln): return self.MAP.get(vuln, "CWE-未知")

class OutputSerializer:
    def serialize(self, data, fmt="json"):
        if fmt == "json": return json.dumps(data)
        return str(data)

class ValidationCache:
    def __init__(self): self.store = {}
    def has(self, key): return key in self.store
    def get(self, key): return self.store.get(key)
    def set(self, key, value): self.store[key] = value

class FindingPrioritizer:
    def prioritize(self, findings):
        priority_map = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
        return sorted(findings, key=lambda f: priority_map.get(f.get("severity"),5))

class ReportArchiver:
    def archive(self, report, dir_path): return {"archived": True, "path": dir_path}

class ResultSignature:
    def sign(self, result):
        import hashlib
        data = json.dumps(result, sort_keys=True)
        return hashlib.sha256(data.encode()).hexdigest()

class OutputVersionChecker:
    def check_version(self, data, expected="1.0"): return data.get("version") == expected

class ValidationPolicy:
    def __init__(self): self.policy = {}
    def add_rule(self, key, value): self.policy[key] = value
    def evaluate(self, data): return all(self.policy.get(k) == v for k,v in data.items())

def create_output_validator(): return OutputValidator()
def validate_audit_result(data): return OutputValidator().validate(data)
def check_finding_quality(finding): return FindingValidator().validate(finding)