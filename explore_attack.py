from mitreattack.stix20 import MitreAttackData

attack = MitreAttackData("enterprise-attack.json")

techniques = attack.get_techniques(remove_revoked_deprecated=True)
print(f"Total techniques loaded: {len(techniques)}")

for i in techniques[:5]:
    print(f"ID: {i.external_references[0].external_id}")
    print(f"Name: {i.name}")
    print(f"Tactic: {[p.phase_name for p in i.kill_chain_phases]}")