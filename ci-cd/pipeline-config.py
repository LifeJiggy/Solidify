"""
Pipeline Configuration Module
Centralized pipeline configuration for CI/CD

Author: Solidify Security Team
Description: Unified pipeline configuration management
"""

import os
import json
import yaml
import logging
import uuid
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, auto
from collections import defaultdict

logger = logging.getLogger(__name__)


class PipelineType(Enum):
    GITHUB = "github"
    GITLAB = "gitlab"
    JENKINS = "jenkins"
    AZURE = "azure"
    CIRCLECI = "circleci"


class EnvironmentType(Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


@dataclass
class PipelineConfig:
    name: str
    pipeline_type: PipelineType
    enabled: bool = True
    triggers: Dict[str, Any] = field(default_factory=dict)
    environment: Dict[str, Any] = field(default_factory=dict)
    secrets: Dict[str, str] = field(default_factory=dict)
    variables: Dict[str, str] = field(default_factory=dict)


@dataclass
class Stage:
    name: str
    command: str
    environment_vars: Dict[str, str] = field(default_factory=dict)
    retry: int = 0
    timeout: int = 300


@dataclass
class Job:
    name: str
    image: Optional[str] = None
    runs_on: Optional[str] = None
    services: List[str] = field(default_factory=list)
    steps: List[Stage] = field(default_factory=list)
    needs: List[str] = field(default_factory=list)
    artifacts: Dict[str, Any] = field(default_factory=dict)
    cache: Dict[str, Any] = field(default_factory=dict)


class PipelineManager:
    def __init__(self):
        self._configs: Dict[str, PipelineConfig] = {}
        self._jobs: Dict[str, Job] = {}

    def create_config(self, name: str, ptype: PipelineType) -> PipelineConfig:
        config = PipelineConfig(name=name, pipeline_type=ptype)
        self._configs[name] = config
        return config

    def add_job(self, job: Job) -> None:
        self._jobs[job.name] = job

    def generate(self, config_name: str) -> str:
        config = self._configs.get(config_name)
        if not config:
            return ""
        
        if config.pipeline_type == PipelineType.GITHUB:
            return self._generate_github(config)
        elif config.pipeline_type == PipelineType.GITLAB:
            return self._generate_gitlab(config)
        elif config.pipeline_type == PipelineType.JENKINS:
            return self._generate_jenkins(config)
        
        return ""

    def _generate_github(self, config: PipelineConfig) -> str:
        result = {"name": config.name, "on": ["push"]}
        for job_name, job in self._jobs.items():
            result["jobs"] = {job_name: self._job_to_dict(job)}
        return yaml.dump(result)

    def _generate_gitlab(self, config: PipelineConfig) -> str:
        result = {"stages": ["build", "test", "deploy"]}
        for job_name, job in self._jobs.items():
            result[job_name] = {"script": [s.command for s in job.steps]}
        return yaml.dump(result)

    def _generate_jenkins(self, config: PipelineConfig) -> str:
        script = ["pipeline {", "    agent any", "    stages {"]
        for job_name, job in self._jobs.items():
            script.append(f"        stage('{job_name}') {")
            script.append("            steps {")
            for step in job.steps:
                script.append(f"                sh '{step.command}'")
            script.append("            }")
            script.append("        }")
        script.append("    }")
        script.append("}")
        return "\n".join(script)

    def _job_to_dict(self, job: Job) -> Dict[str, Any]:
        result = {}
        if job.image:
            result["runs-on"] = job.runs_on
        result["steps"] = [{"run": s.command} for s in job.steps]
        return result


class EnvironmentConfig:
    def __init__(self):
        self._configs: Dict[str, Dict[str, Any]] = {}

    def add_environment(self, name: str, env_type: EnvironmentType,
                       config: Dict[str, Any]) -> None:
        self._configs[name] = {"type": env_type, "config": config}

    def get_environment(self, name: str) -> Optional[Dict[str, Any]]:
        return self._configs.get(name)


class SecretManager:
    def __init__(self):
        self._secrets: Dict[str, str] = {}

    def add_secret(self, name: str, value: str) -> None:
        self._secrets[name] = value

    def get_secret(self, name: str) -> Optional[str]:
        return self._secrets.get(name)


class VariableManager:
    def __init__(self):
        self._variables: Dict[str, str] = {}

    def add_variable(self, name: str, value: str) -> None:
        self._variables[name] = value

    def get_variable(self, name: str) -> Optional[str]:
        return self._variables.get(name)


class TriggerManager:
    def __init__(self):
        self._triggers: Dict[str, List[Dict[str, Any]]] = {}

    def add_trigger(self, event: str, config: Dict[str, Any]) -> None:
        if event not in self._triggers:
            self._triggers[event] = []
        self._triggers[event].append(config)


class ArtifactConfig:
    def __init__(self):
        self._artifacts: Dict[str, Any] = {}

    def add_artifact(self, name: str, path: str, retention: int = 7) -> None:
        self._artifacts[name] = {"path": path, "retention_days": retention}


class CacheConfig:
    def __init__(self):
        self._caches: Dict[str, Any] = {}

    def add_cache(self, key: str, paths: List[str]) -> None:
        self._caches[key] = {"key": key, "paths": paths}


class NotificationConfig:
    def __init__(self):
        self._channels: Dict[str, List[str]] = {}

    def add_channel(self, name: str, recipients: List[str]) -> None:
        self._channels[name] = recipients


class SecurityConfig:
    def __init__(self):
        self._scanning: bool = True
        self._approval: bool = False

    def enable_security_scan(self) -> None:
        self._scanning = True

    def require_approval(self) -> None:
        self._approval = True


class DeploymentConfig:
    def __init__(self):
        self._targets: Dict[str, Dict[str, Any]] = {}

    def add_target(self, name: str, url: str, creds: str) -> None:
        self._targets[name] = {"url": url, "credentials": creds}


class ParallelJob:
    def __init__(self):
        self._jobs: List[Job] = []

    def add(self, job: Job) -> None:
        self._jobs.append(job)

    def to_list(self) -> List[Dict[str, Any]]:
        return [{"name": j.name} for j in self._jobs]


class MatrixJob:
    def __init__(self):
        self._axes: Dict[str, List] = {}

    def add_axis(self, name: str, values: List) -> None:
        self._axes[name] = values

    def generate(self) -> Dict[str, Any]:
        return {"matrix": self._axes}


def create_pipeline(name: str, ptype: PipelineType) -> PipelineConfig:
    manager = PipelineManager()
    return manager.create_config(name, ptype)


def save_config(config: Dict[str, Any], filepath: str) -> bool:
    try:
        with open(filepath, 'w') as f:
            yaml.dump(config, f)
        return True
    except Exception as e:
        logger.error(f"Error saving config: {e}")
        return False


def load_config(filepath: str) -> Optional[Dict[str, Any]]:
    try:
        with open(filepath, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading config: {e}")
        return None


def validate_config(config: Dict[str, Any]) -> Tuple[bool, List[str]]:
    errors = []
    if "name" not in config:
        errors.append("name is required")
    if "pipeline_type" not in config:
        errors.append("pipeline_type is required")
    return len(errors) == 0, errors