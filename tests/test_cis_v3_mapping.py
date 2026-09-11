from compliance.cis_v3_mapping import CIS_V3_CONTROLS


def _control(control_id: str):
    return next(c for c in CIS_V3_CONTROLS if c["control_id"] == control_id)


class TestControl_1_4_RootAccessKeys:
    def test_passes_when_no_such_finding(self):
        assert _control("1.4")["match"]([{"title": "Something else"}]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "Root account has active access keys"}]
        assert _control("1.4")["match"](findings) is False


class TestControl_1_5_RootMfa:
    def test_passes_when_no_such_finding(self):
        assert _control("1.5")["match"]([]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "Root account has no MFA"}]
        assert _control("1.5")["match"](findings) is False


class TestControl_1_10_UserMfa:
    def test_passes_when_no_user_missing_mfa(self):
        assert _control("1.10")["match"]([{"title": "Access key not rotated in 100 days"}]) is True

    def test_fails_when_any_user_missing_mfa(self):
        findings = [{"title": "User has no MFA device"}]
        assert _control("1.10")["match"](findings) is False

    def test_flagged_as_a_conservative_proxy_not_exact(self):
        assert _control("1.10")["exact_match"] is False
        assert _control("1.10")["caveat"]


class TestControl_1_14_AccessKeyRotation:
    def test_passes_when_no_stale_keys(self):
        assert _control("1.14")["match"]([{"title": "User has no MFA device"}]) is True

    def test_fails_when_a_key_is_stale(self):
        findings = [{"title": "Access key not rotated in 120 days"}]
        assert _control("1.14")["match"](findings) is False

    def test_is_an_exact_match_not_a_proxy(self):
        assert _control("1.14")["exact_match"] is True
        assert _control("1.14")["caveat"] is None
