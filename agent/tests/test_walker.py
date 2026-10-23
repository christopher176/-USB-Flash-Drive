"""Safe-traversal guarantees: confinement, symlinks, depth, hidden/system."""
import os
import threading
from pathlib import Path

import pytest

from usb_shield.walker import (DeviceDisconnected, WalkCancelled, iter_walk,
                               resolve_within, snapshot_file,
                               validate_custom_target)

from .conftest import add_file


def collect(root: Path, max_depth: int = 48, targets=None) -> list:
    cancel = threading.Event()
    return [e for e in iter_walk(root, max_depth, cancel, targets=targets)]


def test_hidden_and_nested_entries_enumerated(tmp_path):
    add_file(tmp_path, ".hidden/secret.txt", b"s")
    add_file(tmp_path, "a/b/c/d/e/deep.txt", b"d")
    add_file(tmp_path, "System Volume Information/sys.dat", b"x")
    entries = collect(tmp_path)
    rels = {e.rel for e in entries}
    assert ".hidden/secret.txt" in rels
    assert "a/b/c/d/e/deep.txt" in rels
    assert "System Volume Information/sys.dat" in rels
    hidden = {e.rel for e in entries if e.hidden}
    assert ".hidden" in hidden and ".hidden/secret.txt" in hidden
    system = {e.rel for e in entries if e.system}
    assert "System Volume Information" in system


def test_symlink_never_followed(tmp_path):
    outside = tmp_path.parent / "outside-secret.txt"
    outside.write_bytes(b"TOP SECRET")
    add_file(tmp_path, "normal.txt", b"n")
    os.symlink(outside, tmp_path / "link-secret.txt")
    linkdir = tmp_path.parent / "outside-dir"
    linkdir.mkdir(exist_ok=True)
    (linkdir / "inner.txt").write_bytes(b"inner")
    os.symlink(linkdir, tmp_path / "link-dir")
    entries = collect(tmp_path)
    kinds = {e.rel: e.kind for e in entries}
    assert kinds["link-secret.txt"] == "symlink"
    assert kinds["link-dir"] == "symlink"
    assert "link-dir/inner.txt" not in kinds       # outside content never walked


def test_snapshot_file_refuses_symlink(tmp_path):
    real = tmp_path / "real.txt"
    real.write_bytes(b"data")
    os.symlink(real, tmp_path / "alias.txt")
    with pytest.raises(OSError):
        snapshot_file(tmp_path / "alias.txt", buffer_cap=4096)
    snap = snapshot_file(real, buffer_cap=4096)
    assert snap.body == b"data" and snap.sha256 is not None


def test_resolve_within_blocks_traversal(tmp_path):
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "../../etc/passwd")
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "..")
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "/etc/passwd")
    ok = resolve_within(tmp_path, "Documents/a.txt")
    assert str(ok).startswith(str(tmp_path.resolve()))
    outside = tmp_path.parent / "x"
    link = tmp_path / "escape"
    os.symlink(outside.parent, link)
    with pytest.raises(ValueError):
        resolve_within(tmp_path, "escape/x")


def test_depth_limit(tmp_path):
    add_file(tmp_path, "l1/l2/l3/l4/file.txt", b"x")
    entries = collect(tmp_path, max_depth=2)
    rels = {e.rel for e in entries}
    assert "l1/l2" in rels
    assert "l1/l2/l3/l4/file.txt" not in rels


def test_cancellation_raises(tmp_path):
    for i in range(50):
        add_file(tmp_path, f"f{i}.txt", b"x")
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(WalkCancelled):
        list(iter_walk(tmp_path, 48, cancel))


def test_disappearing_root_raises(tmp_path):
    dev = tmp_path / "dev"
    dev.mkdir()
    import shutil
    shutil.rmtree(dev)
    with pytest.raises(DeviceDisconnected):
        list(iter_walk(dev, 48, threading.Event()))


def test_fifo_and_socket_counted_as_special(tmp_path):
    add_file(tmp_path, "regular.txt", b"x")
    fifo_path = tmp_path / "pipe"
    try:
        os.mkfifo(fifo_path)
    except (AttributeError, OSError):
        pytest.skip("fifo unsupported on this platform")
    entries = collect(tmp_path)
    kinds = {e.rel: e.kind for e in entries}
    assert kinds["pipe"] == "other"
    assert kinds["regular.txt"] == "file"


def test_custom_targets_restrict_scope(tmp_path):
    add_file(tmp_path, "keep/a.txt", b"a")
    add_file(tmp_path, "other/b.txt", b"b")
    entries = collect(tmp_path, targets=["keep"])
    rels = {e.rel for e in entries}
    assert "keep/a.txt" in rels
    assert "other/b.txt" not in rels


def test_custom_target_symlink_rejected(tmp_path):
    real = add_file(tmp_path, "real.txt", b"x")
    os.symlink(real, tmp_path / "link.txt")
    with pytest.raises(ValueError, match="symbolic link"):
        validate_custom_target(tmp_path, "link.txt")
    cancel = threading.Event()
    with pytest.raises(ValueError, match="symbolic link"):
        list(iter_walk(tmp_path, 48, cancel, targets=["link.txt"]))
