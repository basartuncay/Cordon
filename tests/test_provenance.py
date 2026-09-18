from cordon.provenance import LITERAL_PROVENANCE, Provenance, Sensitivity, Tainted, TrustLevel


def prov(source_id, trust, sensitivity=Sensitivity.PRIVATE):
    return Provenance(source_id=source_id, trust=trust, sensitivity=sensitivity)


def test_literal_provenance_is_maximally_trusted_and_public():
    assert LITERAL_PROVENANCE.trust == TrustLevel.USER
    assert LITERAL_PROVENANCE.sensitivity == Sensitivity.PUBLIC


def test_merge_degrades_trust_to_the_least_trusted_side():
    contact_prov = prov("a", TrustLevel.CONTACT, Sensitivity.PUBLIC)
    unknown_prov = prov("b", TrustLevel.UNKNOWN, Sensitivity.PUBLIC)
    assert contact_prov.merge(unknown_prov).trust == TrustLevel.UNKNOWN
    assert unknown_prov.merge(contact_prov).trust == TrustLevel.UNKNOWN


def test_merge_is_order_independent_for_trust():
    user_prov = prov("a", TrustLevel.USER, Sensitivity.PUBLIC)
    contact_prov = prov("b", TrustLevel.CONTACT, Sensitivity.PUBLIC)
    left = user_prov.merge(contact_prov).trust
    right = contact_prov.merge(user_prov).trust
    assert left == right == TrustLevel.CONTACT


def test_merge_escalates_sensitivity_to_private_if_either_side_is():
    public_prov = prov("a", TrustLevel.USER, Sensitivity.PUBLIC)
    private_prov = prov("b", TrustLevel.USER, Sensitivity.PRIVATE)
    assert public_prov.merge(private_prov).sensitivity == Sensitivity.PRIVATE


def test_merge_keeps_public_when_both_sides_are_public():
    a = prov("a", TrustLevel.USER, Sensitivity.PUBLIC)
    b = prov("b", TrustLevel.CONTACT, Sensitivity.PUBLIC)
    assert a.merge(b).sensitivity == Sensitivity.PUBLIC


def test_tainted_combine_of_a_single_value_returns_its_own_provenance():
    p = prov("a", TrustLevel.CONTACT)
    t = Tainted("hi", p)
    assert Tainted.combine(t) == p


def test_tainted_combine_of_three_values_folds_left_to_right():
    a = Tainted("a", prov("a", TrustLevel.USER, Sensitivity.PUBLIC))
    b = Tainted("b", prov("b", TrustLevel.CONTACT, Sensitivity.PUBLIC))
    c = Tainted("c", prov("c", TrustLevel.UNKNOWN, Sensitivity.PRIVATE))
    merged = Tainted.combine(a, b, c)
    assert merged.trust == TrustLevel.UNKNOWN
    assert merged.sensitivity == Sensitivity.PRIVATE


def test_tainted_map_preserves_provenance():
    p = prov("a", TrustLevel.UNKNOWN, Sensitivity.PRIVATE)
    t = Tainted({"sender": "bob@company.example"}, p)
    projected = t.map(lambda d: d["sender"])
    assert projected.value == "bob@company.example"
    assert projected.provenance == p
