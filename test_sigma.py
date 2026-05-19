# test_sigma.py — run from project root, monitoring does NOT need to be active
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.sigma_engine import SimpleSigmaEngine, get_loaded_rules

rules_dir = os.path.join("core", "sigma_rules")
engine = SimpleSigmaEngine(rules_dir)

print(f"\n{'─'*60}")
print(f"  Loaded {len(engine.rules)} rules")
print(f"{'─'*60}")
for r in engine.rules:
    print(f"  [{r['level'].upper():8}] {r['title']}")
    print(f"           Tags: {', '.join(r.get('tags', []))}")
print(f"{'─'*60}\n")

# Test each rule
tests = [
    ("Ransomware", {"fmsecure": {"event_type": "RANSOMWARE_BURST"}, "message": "test"}),
    ("LOLBin",     {"fmsecure": {"event_type": "PROCESS_ATTRIBUTION"},
                    "message": "powershell.exe modified a file"}),
    ("Startup",    {"fmsecure": {"event_type": "CREATED"},
                    "file": {"path": r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\evil.exe"},
                    "message": "CREATED: evil.exe"}),
    ("NoMatch",    {"fmsecure": {"event_type": "CREATED"},
                    "file": {"path": "D:/TEST/notes.txt"},
                    "message": "CREATED: notes.txt"}),
]

for name, event in tests:
    match = engine.evaluate(event)
    if match:
        print(f"  ✅ {name:12} → MATCHED: {match['title']} [{match['level']}]")
    else:
        print(f"  ✅ {name:12} → No match (expected)" if name == "NoMatch"
              else f"  ❌ {name:12} → No match (unexpected!)")