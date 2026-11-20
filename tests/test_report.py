"""Engagement report: the client-facing deliverable."""

from src.handshake import Network, WpaHash
from src.report import build_report, write_report


def _net(essid, bssid, security, hashes=1, pmkid=False):
    return Network(
        bssid=bssid,
        essid=essid,
        security=security,
        has_pmkid=pmkid,
        hashes=[WpaHash(kind="eapol", ap=bssid, sta="11:22:33:44:55:66") for _ in range(hashes)],
        clients={"11:22:33:44:55:66"},
    )


NETS = [
    _net("ExampleNet-A", "aa:bb:cc:dd:ee:ff", "WPA2-PSK"),
    _net("ConvergeExample_2.4GHz", "11:22:33:44:55:66", "WPA2-PSK"),
    _net("CorpWiFi", "aa:bb:cc:dd:ee:ff", "WPA2-Enterprise", hashes=0),
]
RESULTS = {"ExampleNet-A": "ExamplePass1"}


def test_report_states_the_recovered_passphrase_and_risk():
    md = build_report(NETS, RESULTS, wordlist="/w/list.txt", duration="2h 18m")
    assert "1 of 3 in-scope network(s)" in md
    assert "`ExamplePass1`" in md
    assert "| ExampleNet-A |" in md and "HIGH" in md


def test_report_marks_enterprise_as_out_of_scope_not_a_failure():
    """An 802.1X network has no passphrase to recover; reporting it as a plain
    failure would misrepresent the result to the client."""
    md = build_report(NETS, RESULTS, wordlist="/w/list.txt", duration="1m")
    assert "not passphrase-based, out of scope" in md
    section = md.split("### CorpWiFi")[1]
    assert "INFO" in md.split("| CorpWiFi |")[1].split("\n")[0]
    assert "Recovered passphrase" not in section


def test_report_records_what_was_searched_and_what_was_not():
    """A negative result is only meaningful next to the effort behind it."""
    md = build_report(
        NETS, RESULTS, wordlist="/w/list.txt", duration="2h",
        stages_run=["dictionary (8.5M)"],
        stages_skipped=[("mask: 9 digits", "~5h 40m exceeds the 2h budget")],
    )
    assert "dictionary (8.5M)" in md
    assert "mask: 9 digits - ~5h 40m exceeds the 2h budget" in md
    assert "not proven secure" in md


def test_report_always_carries_remediation_and_scope():
    md = build_report(NETS, {}, wordlist="/w/list.txt", duration="1m")
    assert "0 of 3" in md
    for expected in ("WPA3-SAE", "802.11w", "WPS", "Scope and limitations", "No traffic was injected"):
        assert expected in md, expected


def test_report_writes_to_disk(tmp_path):
    out = tmp_path / "sub" / "report.md"
    assert write_report(str(out), build_report(NETS, RESULTS, wordlist="w", duration="1m"))
    assert out.is_file() and "Wireless Assessment" in out.read_text()
