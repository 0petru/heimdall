from heimdall.rules import _load_raw_rules, load_rules
from pathlib import Path

p = Path("./rules/rules.json")

print(load_rules(p))