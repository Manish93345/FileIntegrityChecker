from core.sigma_engine import SimpleSigmaEngine
import os

rules_dir = os.path.join("core", "sigma_rules")
engine = SimpleSigmaEngine(rules_dir)

# Should match ransomware rule
event = {
    "fmsecure": {"event_type": "RANSOMWARE_BURST"},
    "message": "RANSOMWARE BEHAVIOR DETECTED",
    "file": {"path": "D:/TEST/file.docx"}
}
match = engine.evaluate(event)
assert match is not None
assert match["level"] == "critical"
print("✅ Ransomware rule matched:", match["title"])

# Should NOT match anything (INFO created event)
event2 = {
    "fmsecure": {"event_type": "CREATED"},
    "message": "CREATED: D:/TEST/notes.txt",
    "file": {"path": "D:/TEST/notes.txt"}
}
match2 = engine.evaluate(event2)
assert match2 is None
print("✅ Normal CREATED event correctly produced no match")