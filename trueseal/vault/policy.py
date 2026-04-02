"""
TrueSeal Security Policy Validator

Enforces runtime security policies for seal and open operations.
"""

from __future__ import annotations

import copy
import ctypes
import os
import subprocess
from pathlib import Path

import yaml


class PolicyViolationError(Exception):
    """Raised when the current runtime violates a security policy."""


class SealPolicyValidator:
    """Validate and enforce TrueSeal runtime policy rules."""

    DEFAULT_RULES = {
        "deny": ["debugger"],
        "actions": {
            "tamper_detected": "abort",
            "policy_missing": "abort",
        },
    }
    ALLOWED_RULE_KEYS = {"deny", "actions", "expiry"}
    ALLOWED_DENY_OPTIONS = {"root_user", "debugger", "vm_environment", "container", "sandboxed"}
    ALLOWED_CI_RELAXATIONS = {"vm_environment", "container"}

    def __init__(self, raw_yaml_payload=None):
        self.rules = copy.deepcopy(self.DEFAULT_RULES)
        self.policy_missing = False

        if raw_yaml_payload:
            self._load(raw_yaml_payload)

    def _validate_schema(self, rules_dict):
        if not isinstance(rules_dict, dict):
            raise ValueError("Policy must be a dictionary")

        if self._calculate_nesting_depth(rules_dict) > 5:
            raise ValueError("Policy structure too deeply nested (max 5 levels)")

        for key in rules_dict:
            if key not in self.ALLOWED_RULE_KEYS:
                raise ValueError(f"Unknown policy key: {key}")

        deny_rules = rules_dict.get("deny")
        if deny_rules is not None:
            if not isinstance(deny_rules, list):
                raise ValueError("'deny' must be a list")
            for constraint_name in deny_rules:
                if constraint_name not in self.ALLOWED_DENY_OPTIONS:
                    raise ValueError(f"Unknown deny rule: {constraint_name}")

        actions = rules_dict.get("actions")
        if actions is not None:
            if not isinstance(actions, dict):
                raise ValueError("'actions' must be a dictionary")
            for response_action in actions.values():
                if response_action not in {"abort", "warn", "allow"}:
                    raise ValueError(f"Unknown action: {response_action}")

        return True

    @staticmethod
    def _calculate_nesting_depth(obj):
        if not isinstance(obj, (dict, list, tuple)):
            return 1

        max_depth = 1
        stack = [(obj, 1)]

        while stack:
            current_obj, current_depth = stack.pop()
            max_depth = max(max_depth, current_depth)

            if isinstance(current_obj, dict):
                iterable = current_obj.values()
            else:
                iterable = current_obj

            for item in iterable:
                if isinstance(item, (dict, list, tuple)):
                    stack.append((item, current_depth + 1))

        return max_depth

    def _load(self, raw_yaml):
        try:
            cfg = yaml.safe_load(raw_yaml)
            if not isinstance(cfg, dict) or "trueseal" not in cfg:
                raise ValueError("Missing 'trueseal' key in policy")

            policy_rules = cfg["trueseal"]
            self._validate_schema(policy_rules)
            self.rules = policy_rules
            self.policy_missing = False
        except yaml.YAMLError as exc:
            raise ValueError(f"YAML parse error: {exc}") from exc
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"Failed to parse TrueSeal Policy: {exc}") from exc

    def serialize(self) -> bytes:
        return yaml.safe_dump({"trueseal": self.rules}, sort_keys=False).encode("utf-8")

    @classmethod
    def load_from_filesystem(cls, directory_path):
        directory = Path(directory_path)
        validator = cls()

        for policy_path in (directory / "trueseal.yml", directory / ".trueseal.yml"):
            if not policy_path.exists():
                continue

            try:
                validator._load(policy_path.read_text(encoding="utf-8"))
                return validator
            except (OSError, IOError) as exc:
                validator.policy_missing = True
                raise PolicyViolationError(
                    f"Policy file unreadable (possible tampering): {policy_path}. Error: {exc}"
                ) from exc
            except (yaml.YAMLError, ValueError) as exc:
                validator.policy_missing = True
                raise PolicyViolationError(
                    f"Policy file corrupted/malformed: {policy_path}. Using fail-safe defaults. Error: {exc}"
                ) from exc

        validator.policy_missing = True
        return validator

    def _is_debugger_attached_native(self) -> bool:
        if os.name == "nt":
            try:
                is_debugger_present = getattr(ctypes.windll.kernel32, "IsDebuggerPresent", None)
                return bool(is_debugger_present and is_debugger_present())
            except (AttributeError, OSError):
                return False

        try:
            with open("/proc/self/status", "r", encoding="utf-8") as status_file:
                for line in status_file:
                    if line.startswith("TracerPid:"):
                        return int(line.split(":", 1)[1].strip()) != 0
        except (IOError, OSError, ValueError):
            return False

        return False

    def _is_user_elevated(self) -> bool:
        if os.name == "nt":
            try:
                is_user_an_admin = getattr(ctypes.windll.shell32, "IsUserAnAdmin", None)
                return bool(is_user_an_admin and is_user_an_admin())
            except (AttributeError, OSError):
                return False

        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid and geteuid() == 0)

    def _is_virtualized(self) -> bool:
        if os.name == "nt":
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty Model",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=2,
                    check=False,
                )
                model = result.stdout.lower()
                return any(signature in model for signature in ("virtual machine", "vmware", "virtualbox", "hyper-v", "xen"))
            except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
                return False

        try:
            with open("/proc/cpuinfo", "r", encoding="utf-8") as cpuinfo_file:
                content = cpuinfo_file.read().lower()
            return any(signature in content for signature in ("kvm", "vmware", "xen", "hyperv"))
        except (IOError, OSError):
            return False

    def _is_containerized(self) -> bool:
        if os.name == "nt":
            return False

        if os.path.exists("/.dockerenv"):
            return True

        try:
            with open("/proc/1/cgroup", "r", encoding="utf-8") as file_handle:
                content = file_handle.read().lower()
            return any(token in content for token in ("docker", "kubepods", "containerd"))
        except (IOError, OSError):
            return False

    def enforce_runtime_environment(self, force_bypass_env_check: bool = False):
        is_ci_cd = any(
            os.environ.get(var) == "true" for var in ("CI", "GITHUB_ACTIONS")
        ) or "JENKINS_URL" in os.environ

        active_rules = self.rules or self.DEFAULT_RULES
        deny_constraints = set(active_rules.get("deny", []))

        if "root_user" in deny_constraints and self._is_user_elevated():
            raise PolicyViolationError("Vault structural policy denies extraction by elevated/root users.")

        if "debugger" in deny_constraints and self._is_debugger_attached_native():
            raise PolicyViolationError(
                "Vault structural policy denies extraction under active debuggers (Python pdb, GDB, WinDbg, x64dbg, Frida, strace, etc.)."
            )

        if "vm_environment" in deny_constraints:
            if not (force_bypass_env_check and is_ci_cd and "vm_environment" in self.ALLOWED_CI_RELAXATIONS):
                if self._is_virtualized():
                    raise PolicyViolationError("Vault structural policy denies extraction in virtualized environments.")

        if "container" in deny_constraints:
            if not (force_bypass_env_check and is_ci_cd and "container" in self.ALLOWED_CI_RELAXATIONS):
                if self._is_containerized():
                    raise PolicyViolationError("Vault structural policy denies extraction in container environments.")

    def retrieve_action_for_event(self, event_type: str, default_action: str = "abort") -> str:
        active_rules = self.rules or self.DEFAULT_RULES
        action_mapping = active_rules.get("actions", {})
        return action_mapping.get(event_type, default_action)
