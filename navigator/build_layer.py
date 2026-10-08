#!/usr/bin/env python3
"""Build an ATT&CK Navigator layer from the <mitre> tags of rules/local_rules.xml.

Wazuh 4.14 keeps its own copy of the ATT&CK ids, so the rules still carry the
pre-v19 ids. ATT&CK v19 revoked three of them; OLD_TO_V19 maps them so the
layer opens correctly in a v19 Navigator. Mapping checked against the official
enterprise-attack.json (v19.2), "revoked-by" relationships.
"""
import json, re, sys, collections

OLD_TO_V19 = {
    "T1562.004": "T1686",      # Disable or Modify System Firewall
    "T1562.012": "T1685.004",  # Disable or Modify Linux Audit System Log
    "T1070.002": "T1685.006",  # Clear Linux or Mac System Logs
}

rules_path = sys.argv[1] if len(sys.argv) > 1 else "rules/local_rules.xml"
out_path = sys.argv[2] if len(sys.argv) > 2 else "navigator/wazuh-detection-pack-layer.json"

xml = open(rules_path, encoding="utf-8").read()
by_tech = collections.defaultdict(list)
for m in re.finditer(r'<rule id="(\d+)"[^>]*>(.*?)</rule>', xml, re.S):
    for tid in re.findall(r"<id>(T\d+(?:\.\d+)?)</id>", m.group(2)):
        by_tech[OLD_TO_V19.get(tid, tid)].append(m.group(1))

techniques = []
for tid in sorted(by_tech):
    rules = sorted(set(by_tech[tid]))
    techniques.append({
        "techniqueID": tid,
        "score": len(rules),
        "comment": "Wazuh rules: " + ", ".join(rules),
        "enabled": True,
        "showSubtechniques": "." in tid,
    })

layer = {
    "name": "Wazuh Detection Pack coverage",
    "versions": {"attack": "19", "navigator": "5.1.0", "layer": "4.5"},
    "domain": "enterprise-attack",
    "description": "Techniques with at least one custom Wazuh rule that I tested "
                   "(positive test, negative control, documented evasion). Score = number of rules. "
                   "Having a rule does not mean full coverage of the technique: see the evasions in the README.",
    "filters": {"platforms": ["Linux", "IaaS"]},
    "sorting": 0,
    "layout": {"layout": "side", "aggregateFunction": "average",
               "showID": True, "showName": True, "showAggregateScores": False,
               "countUnscored": False, "expandedSubtechniques": "annotated"},
    "hideDisabled": False,
    "techniques": techniques,
    "gradient": {"colors": ["#c6dbef", "#08519c"], "minValue": 1,
                 "maxValue": max(t["score"] for t in techniques)},
    "legendItems": [],
    "metadata": [],
    "links": [],
    "showTacticRowBackground": False,
    "tacticRowBackground": "#dddddd",
    "selectTechniquesAcrossTactics": True,
    "selectSubtechniquesWithParent": False,
    "selectVisibleTechniques": False,
}
json.dump(layer, open(out_path, "w", encoding="utf-8"), indent=2)
print(f"{len(techniques)} techniques, {sum(t['score'] for t in techniques)} rule-technique links -> {out_path}")
for t in techniques:
    print(t["techniqueID"], t["score"], t["comment"])
