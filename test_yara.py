import sys, os
sys.path.insert(0, ".")

from core.yara_engine import YaraEngine

engine = YaraEngine(rules_dir=os.path.join("core", "yara_rules"))
print(f"Engine ready: {engine.is_ready}")

# Create a temp test file
test_path = "test_eicar_temp.txt"
with open(test_path, "w") as f:
    f.write("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")

result = engine.scan_file(test_path)
os.remove(test_path)

if result:
    print(f"✅ YARA matched: {result['rule_name']}")
    print(f"   Family:   {result['family']}")
    print(f"   Severity: {result['severity']}")
    print(f"   MITRE:    {result['mitre']}")
else:
    print("❌ No match — check rule files")