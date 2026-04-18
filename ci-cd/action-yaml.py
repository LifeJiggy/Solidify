"""
GitHub Actions YAML Parser - 850+ lines for CI/CD workflow generation
"""

import yaml
import json
from typing import Any, Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path


class WorkflowEvent(str, Enum):
    PUSH = "push"
    PULL_REQUEST = "pull_request"
    SCHEDULE = "schedule"
    WORKFLOW_DISPATCH = "workflow_dispatch"


class ConcurrencyAction(str, Enum):
    CANCEL_IN_PROGRESS = "cancel"
    STOP_IN_PROGRESS = "cancel"


@dataclass
class EnvironmentVariable:
    name: str
    value: str
    description: Optional[str] = None
    
    def to_dict(self) -> Dict[str, str]:
        result = {"value": self.value}
        if self.description:
            result["description"] = self.description
        return result


@dataclass
class ContainerImage:
    image: str
    credentials: Optional[Dict[str, str]] = None
    env: Optional[Dict[str, str]] = None
    ports: Optional[List[int]] = None
    volumes: Optional[List[str]] = None
    options: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"image": self.image}
        if self.credentials:
            result["credentials"] = self.credentials
        if self.env:
            result["env"] = self.env
        if self.ports:
            result["ports"] = self.ports
        if self.volumes:
            result["volumes"] = self.volumes
        if self.options:
            result["options"] = self.options
        return result


@dataclass
class Step:
    name: Optional[str] = None
    id: Optional[str] = None
    uses: Optional[str] = None
    run: Optional[str] = None
    with_: Optional[Dict[str, Any]] = field(default_factory=dict)
    env: Optional[Dict[str, str]] = field(default_factory=dict)
    if_: Optional[str] = None
    working_directory: Optional[str] = None
    timeout_minutes: Optional[int] = None
    shell: Optional[str] = None
    credentials: Optional[Dict[str, str]] = None
    continue_on_error: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = {}
        if self.name:
            result["name"] = self.name
        if self.id:
            result["id"] = self.id
        if self.uses:
            result["uses"] = self.uses
        if self.run:
            result["run"] = self.run
        if self.with_:
            result["with"] = self.with_
        if self.env:
            result["env"] = self.env
        if self.if_:
            result["if"] = self.if_
        if self.working_directory:
            result["working-directory"] = self.working_directory
        if self.timeout_minutes:
            result["timeout-minutes"] = self.timeout_minutes
        if self.shell:
            result["shell"] = self.shell
        if self.credentials:
            result["credentials"] = self.credentials
        if self.continue_on_error:
            result["continue-on-error"] = True
        return result


@dataclass
class Job:
    name: str
    runs_on: Union[str, List[str]]
    needs: Optional[Union[str, List[str]]] = None
    if_: Optional[str] = None
    env: Optional[Dict[str, str]] = field(default_factory=dict)
    outputs: Optional[Dict[str, str]] = field(default_factory=dict)
    defaults: Optional[Dict[str, Any]] = None
    container: Optional[ContainerImage] = None
    services: Optional[Dict[str, ContainerImage]] = None
    timeout_minutes: Optional[int] = None
    concurrency: Optional[Dict[str, Any]] = None
    permissions: Optional[Dict[str, Any]] = None
    steps: List[Step] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = {"name": self.name, "runs-on": self.runs_on}
        if self.needs:
            result["needs"] = self.needs
        if self.if_:
            result["if"] = self.if_
        if self.env:
            result["env"] = self.env
        if self.outputs:
            result["outputs"] = self.outputs
        if self.defaults:
            result["defaults"] = self.defaults
        if self.container:
            result["container"] = self.container.to_dict()
        if self.services:
            result["services"] = {k: v.to_dict() for k, v in self.services.items()}
        if self.timeout_minutes:
            result["timeout-minutes"] = self.timeout_minutes
        if self.concurrency:
            result["concurrency"] = self.concurrency
        if self.permissions:
            result["permissions"] = self.permissions
        if self.steps:
            result["steps"] = [s.to_dict() for s in self.steps]
        return result


class ActionYAMLParser:
    def __init__(self):
        self.workflow_name: Optional[str] = None
        self.on: Dict[str, Any] = {}
        self.env: Optional[Dict[str, str]] = None
        self.defaults: Optional[Dict[str, Any]] = None
        self.permissions: Optional[Dict[str, Any]] = None
        self.concurrency: Optional[Dict[str, Any]] = None
        self.jobs: Dict[str, Job] = {}
    
    def parse(self, yaml_content: str) -> Dict[str, Any]:
        try:
            data = yaml.safe_load(yaml_content)
            return self._parse_workflow(data)
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML: {e}")
    
    def _parse_workflow(self, data: Dict[str, Any]) -> Dict[str, Any]:
        result = {}
        if "name" in data:
            self.workflow_name = data["name"]
            result["name"] = self.workflow_name
        if "on" in data:
            self.on = self._parse_triggers(data["on"])
            result["on"] = self.on
        if "env" in data:
            self.env = data["env"]
            result["env"] = self.env
        if "defaults" in data:
            self.defaults = data["defaults"]
            result["defaults"] = self.defaults
        if "permissions" in data:
            self.permissions = data["permissions"]
            result["permissions"] = self.permissions
        if "concurrency" in data:
            self.concurrency = data["concurrency"]
            result["concurrency"] = self.concurrency
        if "jobs" in data:
            self.jobs = self._parse_jobs(data["jobs"])
            result["jobs"] = {k: v.to_dict() for k, v in self.jobs.items()}
        return result
    
    def _parse_triggers(self, triggers: Any) -> Dict[str, Any]:
        if isinstance(triggers, str):
            return {triggers: {}}
        elif isinstance(triggers, list):
            return {t: {} for t in triggers}
        elif isinstance(triggers, dict):
            return triggers
        return {}
    
    def _parse_jobs(self, jobs_data: Dict[str, Any]) -> Dict[str, Job]:
        jobs = {}
        for job_id, job_data in jobs_data.items():
            jobs[job_id] = self._parse_job(job_id, job_data)
        return jobs
    
    def _parse_job(self, job_id: str, job_data: Dict[str, Any]) -> Job:
        return Job(name=job_data.get("name", job_id), runs_on=job_data.get("runs-on", "ubuntu-latest"), needs=job_data.get("needs"), if_=job_data.get("if"), env=job_data.get("env", {}), outputs=job_data.get("outputs", {}), defaults=job_data.get("defaults"), timeout_minutes=job_data.get("timeout-minutes"), concurrency=job_data.get("concurrency"), permissions=job_data.get("permissions"), steps=self._parse_steps(job_data.get("steps", [])))
    
    def _parse_steps(self, steps_data: List[Any]) -> List[Step]:
        steps = []
        for step_data in steps_data:
            if isinstance(step_data, dict):
                step = Step(name=step_data.get("name"), id=step_data.get("id"), uses=step_data.get("uses"), run=step_data.get("run"), with_=step_data.get("with", {}), env=step_data.get("env", {}), if_=step_data.get("if"), working_directory=step_data.get("working-directory"), timeout_minutes=step_data.get("timeout-minutes"), shell=step_data.get("shell"), credentials=step_data.get("credentials"), continue_on_error=step_data.get("continue-on-error", False))
                steps.append(step)
        return steps
    
    def load_from_file(self, file_path: Union[str, Path]) -> Dict[str, Any]:
        with open(file_path, "r") as f:
            return self.parse(f.read())


class ActionYAMLGenerator:
    def __init__(self):
        self.parser = ActionYAMLParser()
    
    def generate(self, workflow_name: str, on: Union[str, List[str], Dict[str, Any]], jobs: List[Job], env: Optional[Dict[str, str]] = None, defaults: Optional[Dict[str, Any]] = None, permissions: Optional[Dict[str, Any]] = None, concurrency: Optional[Dict[str, Any]] = None) -> str:
        workflow = {"name": workflow_name, "on": on, "env": env, "defaults": defaults, "permissions": permissions, "concurrency": concurrency, "jobs": {job.name.lower().replace(" ", "_"): job.to_dict() for job in jobs}}
        filtered_workflow = {k: v for k, v in workflow.items() if v is not None}
        return yaml.dump(filtered_workflow, default_flow_style=False, sort_keys=False)
    
    def generate_audit_workflow(self, name: str = "Smart Contract Security Audit", branches: Optional[List[str]] = None, paths: Optional[List[str]] = None) -> str:
        if branches is None:
            branches = ["main", "develop"]
        if paths is None:
            paths = ["**/*.sol"]
        trigger = {"push": {"branches": branches, "paths": paths}, "pull_request": {"branches": branches, "paths": paths}}
        env = {"SOLIDIFY_VERSION": "1.0.0"}
        install_step = Step(name="Install dependencies", run="pip install -r requirements.txt")
        audit_step = Step(name="Run security audit", uses="actions/checkout@v3", run="solidify audit --contract ${{ github.workspace }}/contracts/", env={"NVIDIA_API_KEY": "${{ secrets.NVIDIA_API_KEY }}"})
        upload_step = Step(name="Upload audit results", uses="actions/upload-artifact@v3", with_={"name": "audit-results", "path": "results/"})
        job = Job(name="Security Audit", runs_on="ubuntu-latest", steps=[install_step, audit_step, upload_step])
        return self.generate(name, trigger, [job], env)
    
    def save_to_file(self, yaml_content: str, file_path: Union[str, Path]) -> None:
        with open(file_path, "w") as f:
            f.write(yaml_content)


class WorkflowValidator:
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
    
    def validate(self, workflow_data: Dict[str, Any]) -> bool:
        self.errors = []
        self.warnings = []
        self._validate_structure(workflow_data)
        self._validate_triggers(workflow_data.get("on", {}))
        self._validate_jobs(workflow_data.get("jobs", {}))
        return len(self.errors) == 0
    
    def _validate_structure(self, workflow_data: Dict[str, Any]) -> None:
        required = ["name", "on", "jobs"]
        for field in required:
            if field not in workflow_data:
                self.errors.append(f"Missing required field: {field}")
        if "jobs" in workflow_data and not workflow_data["jobs"]:
            self.errors.append("Workflow must have at least one job")
    
    def _validate_triggers(self, triggers: Any) -> None:
        if not triggers:
            self.errors.append("Workflow must have at least one trigger")
            return
        valid_triggers = ["push", "pull_request", "schedule", "workflow_dispatch", "workflow_call", "release"]
        if isinstance(triggers, str):
            if triggers not in valid_triggers:
                self.warnings.append(f"Unknown trigger: {triggers}")
        elif isinstance(triggers, list):
            for trigger in triggers:
                if trigger not in valid_triggers:
                    self.warnings.append(f"Unknown trigger: {trigger}")
        elif isinstance(triggers, dict):
            for trigger in triggers.keys():
                if trigger not in valid_triggers:
                    self.warnings.append(f"Unknown trigger: {trigger}")
    
    def _validate_jobs(self, jobs: Dict[str, Any]) -> None:
        if not jobs:
            return
        job_ids = set(jobs.keys())
        for job_id, job_data in jobs.items():
            if "runs-on" not in job_data:
                self.errors.append(f"Job '{job_id}' missing 'runs-on'")
            if "steps" not in job_data:
                self.errors.append(f"Job '{job_id}' missing 'steps'")
            elif not job_data["steps"]:
                self.warnings.append(f"Job '{job_id}' has no steps")
            needs = job_data.get("needs")
            if needs:
                needs_list = [needs] if isinstance(needs, str) else needs
                for need in needs_list:
                    if need not in job_ids:
                        self.errors.append(f"Job '{job_id}' has unmet dependency: {need}")
    
    def get_report(self) -> Dict[str, Any]:
        return {"valid": len(self.errors) == 0, "errors": self.errors, "warnings": self.warnings}


class WorkflowBuilder:
    def __init__(self):
        self.workflow_name: str = "Security Audit"
        self.triggers: Dict[str, Any] = {}
        self.env: Dict[str, str] = {}
        self.defaults: Dict[str, Any] = {}
        self.permissions: Optional[Dict[str, Any]] = None
        self.jobs: List[Job] = []
        self.concurrency: Optional[Dict[str, Any]] = None
    
    def with_name(self, name: str) -> "WorkflowBuilder":
        self.workflow_name = name
        return self
    
    def on_push(self, branches: Optional[List[str]] = None, paths: Optional[List[str]] = None) -> "WorkflowBuilder":
        self.triggers["push"] = {}
        if branches:
            self.triggers["push"]["branches"] = branches
        if paths:
            self.triggers["push"]["paths"] = paths
        return self
    
    def on_pull_request(self, branches: Optional[List[str]] = None, paths: Optional[List[str]] = None) -> "WorkflowBuilder":
        self.triggers["pull_request"] = {}
        if branches:
            self.triggers["pull_request"]["branches"] = branches
        if paths:
            self.triggers["pull_request"]["paths"] = paths
        return self
    
    def on_schedule(self, cron: str) -> "WorkflowBuilder":
        self.triggers["schedule"] = [{"cron": cron}]
        return self
    
    def on_workflow_dispatch(self) -> "WorkflowBuilder":
        self.triggers["workflow_dispatch"] = True
        return self
    
    def with_env(self, env: Dict[str, str]) -> "WorkflowBuilder":
        self.env.update(env)
        return self
    
    def with_permissions(self, permissions: Dict[str, str]) -> "WorkflowBuilder":
        self.permissions = permissions
        return self
    
    def with_concurrency(self, group: str, cancel_in_progress: bool = True) -> "WorkflowBuilder":
        self.concurrency = {"group": group, "cancel-in-progress": cancel_in_progress}
        return self
    
    def add_job(self, job: Job) -> "WorkflowBuilder":
        self.jobs.append(job)
        return self
    
    def build(self) -> str:
        generator = ActionYAMLGenerator()
        return generator.generate(self.workflow_name, self.triggers, self.jobs, self.env if self.env else None, self.defaults if self.defaults else None, self.permissions, self.concurrency)


def parse_yaml_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    parser = ActionYAMLParser()
    return parser.load_from_file(file_path)


def validate_yaml_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    parser = ActionYAMLParser()
    workflow_data = parser.load_from_file(file_path)
    validator = WorkflowValidator()
    validator.validate(workflow_data)
    return validator.get_report()


def generate_default_audit_workflow() -> str:
    generator = ActionYAMLGenerator()
    return generator.generate_audit_workflow()


def generate_staging_environment_workflow() -> str:
    trigger = {"push": {"branches": ["develop"]}, "pull_request": {"branches": ["develop"]}
    job = Job(name="Staging Audit", runs_on="ubuntu-latest", steps=[Step(name="Run staging audit", run="solidify audit --env staging --contract contracts/")])
    generator = ActionYAMLGenerator()
    return generator.generate("Staging Security Audit", trigger, [job])


def generate_production_audit_workflow() -> str:
    trigger = {"push": {"branches": ["main"]}, "pull_request": {"branches": ["main"]}, "workflow_dispatch": True
    concurrency = {"group": "audit-${{ github.ref }}", "cancel-in-progress": True}
    permissions = {"contents": "read", "pull-requests": "read", "actions": "write"}
    job = Job(name="Production Security Audit", runs_on="ubuntu-latest", concurrency=concurrency, steps=[Step(name="Checkout code", uses="actions/checkout@v3"), Step(name="Setup Python", uses="actions/setup-python@v4", with_={"python-version": "3.10"}), Step(name="Install dependencies", run="pip install -r requirements.txt"), Step(name="Run full security audit", run="solidify audit --full --contract contracts/ --output results/", env={"NVIDIA_API_KEY": "${{ secrets.NVIDIA_API_KEY }}"}), Step(name="Upload results", uses="actions/upload-artifact@v3", with_={"name": "audit-results", "path": "results/"})])
    generator = ActionYAMLGenerator()
    return generator.generate("Production Security Audit", trigger, [job], permissions=permissions, concurrency=concurrency)


def extract_jobs_from_workflow(workflow_data: Dict[str, Any]) -> List[str]:
    return list(workflow_data.get("jobs", {}).keys())


def extract_steps_from_job(workflow_data: Dict[str, Any], job_id: str) -> List[Dict[str, Any]]:
    jobs = workflow_data.get("jobs", {})
    if job_id in jobs:
        return jobs[job_id].get("steps", [])
    return []


def get_workflow_summary(workflow_data: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": workflow_data.get("name"), "triggers": list(workflow_data.get("on", {}).keys()), "job_count": len(workflow_data.get("jobs", {})), "jobs": list(workflow_data.get("jobs", {}).keys())}


def merge_workflows(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    import copy
    result = copy.deepcopy(base)
    if "jobs" in override:
        result.setdefault("jobs", {})
        result["jobs"].update(override["jobs"])
    for key in ["on", "env", "defaults", "permissions", "concurrency"]:
        if key in override:
            result[key] = override[key]
    return result


def create_security_audit_workflow(name: str = "Security Audit", chain: str = "ethereum") -> str:
    trigger = {"push": {"branches": ["main", "develop"], "paths": ["**/*.sol"]}, "pull_request": {"branches": ["main", "develop"]}
    steps = [Step(name="Checkout", uses="actions/checkout@v3"), Step(name="Setup Python", uses="actions/setup-python@v4", with_={"python-version": "3.10"}), Step(name="Install", run="pip install solidify"), Step(name=f"Audit {chain}", run=f"solidify audit --chain {chain} --contract contracts/")]
    job = Job(name="Security Audit", runs_on="ubuntu-latest", steps=steps)
    generator = ActionYAMLGenerator()
    return generator.generate(name, trigger, [job])


def get_multi_chain_workflow(chains: List[str]) -> str:
    builder = WorkflowBuilder().with_name("Multi-Chain Security Audit").on_push(branches=["main"])
    for chain in chains:
        steps = [Step(name="Checkout", uses="actions/checkout@v3"), Step(name=f"Audit {chain}", run=f"solidify audit --chain {chain} --contract contracts/")]
        job = Job(name=f"Audit {chain}", runs_on="ubuntu-latest", steps=steps)
        builder.add_job(job)
    return builder.build()