from app.services.mitre_mapper import get_all_techniques, map_to_mitre


def test_maps_known_event_type():
    result = map_to_mitre("port_scan")
    assert result["technique_id"] == "T1046"
    assert result["tactic"] == "Reconnaissance"


def test_root_login_mapping_does_not_mutate_shared_mapping():
    root_result = map_to_mitre("ssh_login", {"username": "root"})
    normal_result = map_to_mitre("ssh_login", {"username": "admin"})
    assert root_result["technique_id"] == "T1110.003"
    assert normal_result["technique_id"] == "T1110"


def test_unknown_event_has_safe_fallback():
    result = map_to_mitre("not-a-real-event")
    assert result["technique_id"] == "T1000"
    assert result["tactic"] == "Unknown"


def test_all_techniques_are_unique():
    techniques = get_all_techniques()
    ids = [technique["id"] for technique in techniques]
    assert len(ids) == len(set(ids))