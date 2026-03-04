from __future__ import annotations

import json
import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REQUIRED_FIELDS = {
	"id",
	"msg",
	"proto",
	"src",
	"dst",
	"src_port",
	"dst_port",
	"content",
	"priority",
}

ALLOWED_PROTOCOLS = {"any", "tcp", "udp", "icmp", "ip"}


class RuleLoadError(ValueError):
	pass


@dataclass(frozen=True)
class Rule:
	id: int
	msg: str
	proto: str
	src: str
	dst: str
	src_port: int | str
	dst_port: int | str
	content: str
	priority: int


def _normalize_port(value: Any, field_name: str, rule_id: int | None = None) -> int | str:
	if isinstance(value, str):
		io_value = value.strip().lower()
		if io_value == "any":
			return "any"
		if io_value.isdigit():
			value = int(io_value)
		else:
			_raise_rule_error(f"{field_name} must be an integer or 'any'", rule_id)

	if isinstance(value, int):
		if 0 <= value <= 65535:
			return value
		_raise_rule_error(f"{field_name} must be between 0 and 65535", rule_id)

	_raise_rule_error(f"{field_name} must be an integer or 'any'", rule_id)
	return "any"


def _normalize_rule(raw_rule: dict[str, Any], position: int) -> Rule:
	missing = REQUIRED_FIELDS.difference(raw_rule.keys())
	if missing:
		raise RuleLoadError(f"Rule at index {position} missing required fields: {sorted(missing)}")

	try:
		rule_id = int(raw_rule["id"])
	except Exception as exc:
		raise RuleLoadError(f"Rule at index {position}: 'id' must be an integer") from exc

	msg = str(raw_rule["msg"]).strip()
	if not msg:
		_raise_rule_error("msg must be a non-empty string", rule_id)

	proto = str(raw_rule["proto"]).strip().lower()
	if proto not in ALLOWED_PROTOCOLS:
		_raise_rule_error(
			f"proto must be one of {sorted(ALLOWED_PROTOCOLS)}",
			rule_id,
		)

	src = str(raw_rule["src"]).strip().lower()
	dst = str(raw_rule["dst"]).strip().lower()
	if not src or not dst:
		_raise_rule_error("src and dst must be non-empty", rule_id)

	src_port = _normalize_port(raw_rule["src_port"], "src_port", rule_id=rule_id)
	dst_port = _normalize_port(raw_rule["dst_port"], "dst_port", rule_id=rule_id)

	content = str(raw_rule["content"])

	try:
		priority = int(raw_rule["priority"])
	except Exception as exc:
		raise RuleLoadError(f"Rule id={rule_id}: priority must be an integer") from exc
	if priority < 1:
		_raise_rule_error("priority must be >= 1", rule_id)

	return Rule(
		id=rule_id,
		msg=msg,
		proto=proto,
		src=src,
		dst=dst,
		src_port=src_port,
		dst_port=dst_port,
		content=content,
		priority=priority,
	)


def _raise_rule_error(message: str, rule_id: int | None = None) -> None:
	if rule_id is not None:
		raise RuleLoadError(f"Rule id={rule_id}: {message}")
	raise RuleLoadError(message)

# loads the rules into a dict
def _load_raw_rules(path: Path) -> list[dict[str, Any]]:
	if not path.exists(): # verifies if path exists
		raise RuleLoadError(f"Rules file not found: {path}")

	suffix = path.suffix.lower() 
	if suffix == ".json": # checks if is json
		try:
			payload = json.loads(path.read_text(encoding="utf-8"))
		except json.JSONDecodeError as exc:
			raise RuleLoadError(f"Invalid JSON in {path}: {exc}") from exc

	elif suffix in {".yml", ".yaml"}: # YAML format
        
        # import checker
		try:
			yaml_module = importlib.import_module("yaml")
		except ModuleNotFoundError as exc:
			raise RuleLoadError(
				"YAML rules require PyYAML. Install with: python -m pip install pyyaml"
			) from exc
		
        # rules loader
		try:
			payload = yaml_module.safe_load(path.read_text(encoding="utf-8"))
		except Exception as exc:
			raise RuleLoadError(f"Invalid YAML in {path}: {exc}") from exc

	else:
		raise RuleLoadError("Unsupported rules format. Use .json, .yml, or .yaml")
		
    # rejects invalid formats early
	if not isinstance(payload, list):
		raise RuleLoadError("Rules file must contain a list of rule objects")

	# validates each rule if its in the correct format
	normalized_payload: list[dict[str, Any]] = []
	for index, rule in enumerate(payload):
		if not isinstance(rule, dict):
			raise RuleLoadError(f"Rule at index {index} must be an object")
		normalized_payload.append(rule)

	return normalized_payload


def load_rules(path: str | Path) -> list[Rule]:
	"""Load and validate IDS rules from JSON/YAML."""
	file_path = Path(path)
	raw_rules = _load_raw_rules(file_path)

	rules: list[Rule] = []
	seen_ids: set[int] = set()

	for index, raw_rule in enumerate(raw_rules):
		print(raw_rule)
		print("===")
		rule = _normalize_rule(raw_rule, index)
		if rule.id in seen_ids:
			raise RuleLoadError(f"Duplicate rule id found: {rule.id}")
		seen_ids.add(rule.id)
		rules.append(rule)

	return rules


def load_rules_as_dicts(path: str | Path) -> list[dict[str, Any]]:
	"""Load rules and return plain dicts (for JSON serialization/debugging)."""
	return [rule.__dict__.copy() for rule in load_rules(path)]
