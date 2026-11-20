"""The live stage status line.

It has to keep moving on its own: hashcat reports once every 5 seconds and a
mask stage runs for minutes, so a line that only changed on new data looked
hung - and some terminals never repainted the bare carriage-return update.
"""

import io
import time

from src.hashcat.crack import _StatusLine


class _Tty(io.StringIO):
    def isatty(self):
        return True


def _line(monkeypatch):
    out = _Tty()
    monkeypatch.setattr("sys.stdout", out)
    return out


def test_repaints_on_its_own_without_new_data(monkeypatch):
    out = _line(monkeypatch)
    s = _StatusLine("[ 6/19] ISP mask")
    s.start()
    try:
        time.sleep(_StatusLine._INTERVAL * 4)
    finally:
        s.clear()
    written = out.getvalue()
    # Several frames of the spinner must have been emitted with no update() call.
    assert written.count("\r") >= 3, written[:200]
    assert any(f in written for f in _StatusLine._FRAMES)


def test_update_shows_the_detail(monkeypatch):
    out = _line(monkeypatch)
    s = _StatusLine("[ 7/19] mask")
    s.update("50.5 kH/s   67.8%   3m 48s")
    s.clear()
    assert "50.5 kH/s" in out.getvalue()
    assert "[ 7/19] mask" in out.getvalue()


def test_clear_stops_the_thread_and_wipes_the_line(monkeypatch):
    out = _line(monkeypatch)
    s = _StatusLine("x")
    s.start()
    s.clear()
    assert s._thread is None
    assert out.getvalue().endswith("\r")
    # No further output after clear().
    before = len(out.getvalue())
    time.sleep(_StatusLine._INTERVAL * 3)
    assert len(out.getvalue()) == before, "the heartbeat must stop on clear()"


def test_silent_when_not_a_tty(monkeypatch):
    out = io.StringIO()  # isatty() is False
    monkeypatch.setattr("sys.stdout", out)
    s = _StatusLine("x")
    s.start()
    s.update("something")
    s.clear()
    assert out.getvalue() == "", "piped output must stay clean for logs"


def test_leaves_a_permanent_line_periodically(monkeypatch):
    """An in-place update is worthless if the terminal stops repainting: a
    stalled pane showed a snapshot minutes old and the run looked hung."""
    out = _line(monkeypatch)
    monkeypatch.setattr(_StatusLine, "_INTERVAL", 0.02)
    monkeypatch.setattr(_StatusLine, "_CHECKPOINT", 0.1)
    s = _StatusLine("[10/19] hybrid")
    s.update("50.5 kH/s   12.0%   0m 30s")
    s.start()
    try:
        time.sleep(0.6)
    finally:
        s.clear()
    assert out.getvalue().count("\n") >= 2, "expected periodic newline-terminated lines"
    assert "[10/19] hybrid" in out.getvalue()


def test_checkpoints_still_appear_when_not_a_tty(monkeypatch):
    """Piped output showed nothing at all between stages."""
    out = io.StringIO()  # isatty() False
    monkeypatch.setattr("sys.stdout", out)
    monkeypatch.setattr(_StatusLine, "_INTERVAL", 0.02)
    monkeypatch.setattr(_StatusLine, "_CHECKPOINT", 0.1)
    s = _StatusLine("[10/19] hybrid")
    s.update("50.5 kH/s   12.0%")
    s.start()
    try:
        time.sleep(0.6)
    finally:
        s.clear()
    text = out.getvalue()
    assert "[10/19] hybrid" in text and text.count("\n") >= 2
    assert "50.5 kH/s" in text, "checkpoints must carry the live detail, not 'starting...'"
    assert not any(f * 3 in text for f in "|/-"), "no spinner frames in piped output"
