"""
Solidify CI/CD Integration Package

This package provides CI/CD pipeline integrations for automated security audits.
Supports GitHub Actions, GitLab CI, Jenkins, and custom pipeline configurations.

Author: Peace Stephen
Project: Solidify - Web3 Smart Contract Security Auditor
Hackathon: GDG Abuja × Build with AI Sprint
"""

from .github_action import GitHubActionGenerator
from .gitlab_ci import GitLabCIGenerator
from .jenkins import JenkinsPipelineGenerator
from .pipeline_config import PipelineConfig, PipelineRunner
from .action_yaml import ActionYAMLParser

__version__ = "1.0.0"
__all__ = [
    "GitHubActionGenerator",
    "GitLabCIGenerator",
    "JenkinsPipelineGenerator", 
    "PipelineConfig",
    "PipelineRunner",
    "ActionYAMLParser",
]

CI_CD_PLATFORMS = ["github", "gitlab", "jenkins", "azure", "circleci", "travis"]

AUDIT_TRIGGERS = {
    "push": {"branches": ["main", "develop"], "paths": ["**.sol", "**/*.sol"]},
    "pull_request": {"branches": ["main", "develop"]},
    "schedule": {"cron": "0 0 * * 0"},
    "manual": {"description": "Run security audit manually"},
}

DEFAULT_AUDIT_STEPS = [
    {"name": "Install dependencies", "run": "pip install -r requirements.txt"},
    {"name": "Install Solc", "run": "npm install -g solc"},
    {"name": "Run static analysis", "run": "slither . --json results.json"},
    {"name": "Run AI security audit", "run": "solidify audit --contract contracts/"},
    {"name": "Upload results", "uses": "actions/upload-artifact@v3", "with": {"name": "audit-results", "path": "results/"}},
]

def get_platform_generator(platform):
    """Get the appropriate pipeline generator for the platform."""
    generators = {
        "github": GitHubActionGenerator,
        "gitlab": GitLabCIGenerator,
        "jenkins": JenkinsPipelineGenerator,
    }
    return generators.get(platform.lower())


def create_audit_pipeline(platform, **options):
    """Create a security audit pipeline for the specified platform."""
    generator_class = get_platform_generator(platform)
    if not generator_class:
        raise ValueError(f"Unsupported platform: {platform}")
    
    generator = generator_class(**options)
    return generator.generate()


def validate_pipeline_config(config):
    """Validate pipeline configuration structure."""
    required_fields = ["name", "steps"]
    for field in required_fields:
        if field not in config:
            raise ValueError(f"Missing required field: {field}")
    
    if not isinstance(config["steps"], list) or len(config["steps"]) == 0:
        raise ValueError("steps must be a non-empty list")
    
    return True


def merge_pipeline_configs(base, override):
    """Merge two pipeline configurations."""
    import copy
    result = copy.deepcopy(base)
    
    if "steps" in override:
        result.setdefault("steps", [])
        result["steps"].extend(override["steps"])
    
    for key, value in override.items():
        if key != "steps":
            result[key] = value
    
    return result


def get_audit_environment_vars(platform):
    """Get required environment variables for the platform."""
    env_vars = {
        "github": ["GITHUB_TOKEN", "NVIDIA_API_KEY"],
        "gitlab": ["GITLAB_TOKEN", "NVIDIA_API_KEY"],
        "jenkins": ["JENKINS_URL", "NVIDIA_API_KEY"],
    }
    return env_vars.get(platform.lower(), [])


def generate_webhook_payload(audit_results, platform):
    """Generate webhook payload for audit results."""
    payload = {
        "status": "completed",
        "results": audit_results,
        "platform": platform,
        "timestamp": __import__("datetime").datetime.now().isoformat(),
    }
    return payload


def parse_audit_results_file(file_path):
    """Parse audit results from various formats."""
    import json
    
    if file_path.endswith(".json"):
        with open(file_path) as f:
            return json.load(f)
    elif file_path.endswith(".xml"):
        import xml.etree.ElementTree as ET
        tree = ET.parse(file_path)
        return tree.getroot()
    else:
        raise ValueError(f"Unsupported file format: {file_path}")