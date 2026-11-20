"""Single-instance lock: two concurrent runs destroy each other's work."""

import os

from src.utils import _pid_alive, acquire_run_lock, release_run_lock


def test_lock_is_free_then_held(tmp_path):
    lock = str(tmp_path / ".run.lock")
    assert acquire_run_lock(lock) is None
    assert open(lock).read().strip() == str(os.getpid())
    # Re-acquiring from the same process is not a conflict.
    assert acquire_run_lock(lock) is None
    release_run_lock(lock)
    assert not os.path.exists(lock)


def test_a_live_holder_blocks_a_second_run(tmp_path):
    lock = str(tmp_path / ".run.lock")
    # PID 1 always exists and is not us.
    with open(lock, "w") as f:
        f.write("1")
    holder = acquire_run_lock(lock)
    assert holder == 1, "a live holder must block the second run"


def test_a_stale_lock_is_taken_over(tmp_path):
    lock = str(tmp_path / ".run.lock")
    dead = _find_dead_pid()
    with open(lock, "w") as f:
        f.write(str(dead))
    assert acquire_run_lock(lock) is None, "a dead holder must not block a run"
    assert open(lock).read().strip() == str(os.getpid())
    release_run_lock(lock)


def test_a_corrupt_lock_never_blocks(tmp_path):
    lock = str(tmp_path / ".run.lock")
    with open(lock, "w") as f:
        f.write("not-a-pid")
    assert acquire_run_lock(lock) is None
    release_run_lock(lock)


def test_release_does_not_remove_another_process_lock(tmp_path):
    lock = str(tmp_path / ".run.lock")
    with open(lock, "w") as f:
        f.write("1")
    release_run_lock(lock)
    assert os.path.exists(lock), "must not drop a lock this process does not own"


def test_pid_alive_basics():
    assert _pid_alive(os.getpid()) is True
    assert _pid_alive(0) is False
    assert _pid_alive(-5) is False
    assert _pid_alive(_find_dead_pid()) is False


def _find_dead_pid() -> int:
    """A PID that is not currently in use."""
    for candidate in range(400000, 300000, -1):
        if not _pid_alive(candidate):
            return candidate
    raise AssertionError("no free pid found")
