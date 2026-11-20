"""The end-of-run summary - the number the client sees."""

from main import print_summary

RESULTS = [
    ("ConvergeExample_2.4GHz", None),
    ("ExampleNet-K", None),
    ("Example Family", None),
]
EARLIER = {"ExampleNet-A": "ExamplePass1", "ExampleNet-B": "ExamplePass2"}


def test_previously_recovered_networks_count_towards_the_total(capsys):
    """A network cracked by an earlier run is skipped this time, and used to
    vanish from the count: an estate with two passphrases in hand reported
    '0 of 9 recovered'."""
    print_summary(RESULTS, skipped_count=4, previously=EARLIER)
    out = capsys.readouterr().out
    assert "2 of 5 network(s) recovered" in out
    assert "0 new this run, 2 from earlier" in out
    assert "ExamplePass1" in out and "ExamplePass2" in out
    assert "earlier run" in out


def test_new_hits_are_not_double_counted(capsys):
    """A network cracked this run is also on disk from the write that just
    happened; it must appear once, as a new hit."""
    results = [("ExampleNet-A", "ExamplePass1"), ("ExampleNet-K", None)]
    print_summary(results, skipped_count=0, previously={"ExampleNet-A": "ExamplePass1"})
    out = capsys.readouterr().out
    assert "1 of 2 network(s) recovered" in out
    assert out.count("ExamplePass1") == 1
    assert "earlier run" not in out


def test_summary_without_history_is_unchanged(capsys):
    print_summary(RESULTS, skipped_count=0)
    out = capsys.readouterr().out
    assert "0 of 3 network(s) recovered" in out
    assert "from earlier" not in out


def test_recovered_networks_are_listed_before_failures(capsys):
    print_summary([("A", "pw-a"), ("B", None)], previously={"C": "pw-c"})
    out = capsys.readouterr().out
    assert out.index("pw-a") < out.index("pw-c") < out.index("not found")
