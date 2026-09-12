from compliance.cis_azure_mapping import CIS_AZURE_CONTROLS, CIS_AZURE_TOTAL_CONTROLS


def _control(control_id: str):
    return next(c for c in CIS_AZURE_CONTROLS if c["control_id"] == control_id)


class TestControl_4_1_SecureTransfer:
    def test_passes_when_no_such_finding(self):
        assert _control("4.1")["match"]([{"title": "Something else"}]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "CIS 4.1: Secure transfer required is disabled"}]
        assert _control("4.1")["match"](findings) is False

    def test_is_an_exact_match_not_a_proxy(self):
        assert _control("4.1")["exact_match"] is True
        assert _control("4.1")["caveat"] is None


class TestControl_4_17_BlobPublicAccess:
    def test_passes_when_no_such_finding(self):
        assert _control("4.17")["match"]([]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "CIS 4.17: Storage account allows Blob anonymous access"}]
        assert _control("4.17")["match"](findings) is False


class TestControl_7_1_RdpRestricted:
    def test_passes_when_no_such_finding(self):
        assert _control("7.1")["match"]([{"title": "CIS 7.2: SSH access from the internet is not restricted"}]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "CIS 7.1: RDP access from the internet is not restricted"}]
        assert _control("7.1")["match"](findings) is False


class TestControl_7_2_SshRestricted:
    def test_passes_when_no_such_finding(self):
        assert _control("7.2")["match"]([]) is True

    def test_fails_when_finding_present(self):
        findings = [{"title": "CIS 7.2: SSH access from the internet is not restricted"}]
        assert _control("7.2")["match"](findings) is False


class TestNoAzureSecurityHubEquivalent:
    def test_every_control_has_an_empty_security_hub_id(self):
        for control in CIS_AZURE_CONTROLS:
            assert control["security_hub_id"] == ""


class TestTotalControlCount:
    def test_matches_prowler_source(self):
        assert CIS_AZURE_TOTAL_CONTROLS == 159
        assert len(CIS_AZURE_CONTROLS) == 4
