"""Safe filesystem traversal.

Guarantees:
  * the walk never escapes the selected device root (realpath confinement,
    no symlink following at any level, mount-point jail via st_dev)
  * directory-loop protection via (st_dev, st_ino) tracking
  * explicit enumeration of hidden and system entries
  * permission / disappearing-device errors are surfaced, never swallowed
  * cooperative cancellation

Nothing in this module executes, opens for writing, or modifies the device.
"""
from __future__ import annotations

import os
import stat as statmod
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterator, Optional

SYSTEM_DIR_NAMES = {
    "system volume information", "$recycle.bin", "recycler", "found.000",
    ".trash-1000", ".trashes", ".fseventsd", ".spotlight-v100", ".documentrevisions-v100",
}


class DeviceDisconnected(Exception):
    """The device root became inaccessible mid-scan (removed / unmounted)."""


class WalkCancelled(Exception):
    pass


@dataclass
class WalkEntry:
    abspath: Path
    rel: str                      # POSIX-style path relative to device root
    name: str
    kind: str                     # "file" | "dir" | "symlink" | "other"
    hidden: bool
    system: bool
    size: int = 0
    mtime: float = 0.0
    st: Optional[os.stat_result] = None


@dataclass
class WalkStats:
    dirs: int = 0
    dirs_failed: int = 0
    files: int = 0
    symlinks: int = 0
    special: int = 0
    depth_limited: int = 0
    mount_jail_skips: int = 0
    loop_skips: int = 0


def _is_hidden(name: str, st: Optional[os.stat_result]) -> bool:
    if name.startswith(".") and name not in (".", ".."):
        return True
    attrs = getattr(st, "st_file_attributes", 0) if st else 0
    return bool(attrs & 0x02)  # FILE_ATTRIBUTE_HIDDEN on Windows


def _is_system_rel(rel: str, st: Optional[os.stat_result]) -> bool:
    if any(part.lower() in SYSTEM_DIR_NAMES for part in rel.split("/") if part):
        return True
    attrs = getattr(st, "st_file_attributes", 0) if st else 0
    return bool(attrs & 0x04)  # FILE_ATTRIBUTE_SYSTEM


def resolve_within(root: Path, rel: str) -> Path:
    """Resolve ``rel`` under ``root`` guaranteeing the result stays inside the
    device.  Absolute paths, parent references, NUL bytes and symlink escapes
    are all rejected with ValueError."""
    rel = (rel or "").strip()
    if not rel or "\x00" in rel:
        raise ValueError("invalid path")
    if rel.startswith(("/", "\\")) or (len(rel) > 2 and rel[1] == ":"):
        raise ValueError("absolute paths are not allowed")
    norm = rel.replace("\\", "/")
    parts = [p for p in norm.split("/") if p not in ("", ".")]
    if not parts:
        raise ValueError("invalid path")
    if any(p == ".." for p in parts):
        raise ValueError("parent-directory references are not allowed")
    candidate = root / "/".join(parts)
    real_root = os.path.realpath(root)
    real_target = os.path.realpath(candidate)
    if real_target != real_root and not real_target.startswith(real_root + os.sep):
        raise ValueError("path escapes the selected device")
    return Path(real_target)


def validate_custom_target(root: Path, rel: str) -> tuple[Path, os.stat_result]:
    """Full validation for custom-scan targets. Returns (resolved, lstat).
    Rejects: traversal, absolute paths, missing entries, symlinks at the
    selection point, and non-file/non-directory targets."""
    target = resolve_within(root, rel)
    raw = root / rel.replace("\\", "/")
    try:
        lst = os.lstat(raw)
    except FileNotFoundError as exc:
        raise ValueError(f"custom path does not exist: {rel}") from exc
    if statmod.S_ISLNK(lst.st_mode):
        raise ValueError(f"custom path is a symbolic link and cannot be "
                         f"selected: {rel}")
    if not (statmod.S_ISREG(lst.st_mode) or statmod.S_ISDIR(lst.st_mode)):
        raise ValueError(f"custom path is not a regular file or directory: {rel}")
    return target, lst


def open_nofollow(path: Path) -> int:
    """Open a file for reading, refusing symlinks. Caller closes the fd."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    return os.open(str(path), flags)


@dataclass
class FileSnapshot:
    size: int
    header: bytes = b""          # first up-to-4 KiB
    body: Optional[bytes] = None  # full content when <= buffer cap
    sha256: Optional[str] = None  # only when fully read
    truncated: bool = False       # larger than the in-memory buffer cap
    changed: bool = False         # modified while we were reading it


def snapshot_file(path: Path, buffer_cap: int, header_bytes: int = 4096) -> FileSnapshot:
    """Read a file safely for inspection.

    Small files are read fully in memory (hash + header + body); large files
    contribute only their header and are *streamed* separately by engines
    that need more.  Detects modification during the read via fstat before
    and after.
    """
    import hashlib

    fd = open_nofollow(path)   # raises OSError/ELOOP on symlink
    with os.fdopen(fd, "rb", closefd=True) as fh:
        st_before = os.fstat(fh.fileno())
        if not statmod.S_ISREG(st_before.st_mode):
            raise OSError("not a regular file")
        size = st_before.st_size
        snap = FileSnapshot(size=size)
        if size > buffer_cap:
            snap.header = fh.read(header_bytes)
            snap.truncated = True
        else:
            buf = fh.read(buffer_cap + 1)
            if len(buf) > buffer_cap or (size == buffer_cap and len(buf) == buffer_cap + 1):
                snap.header = buf[:header_bytes]
                snap.truncated = True
            else:
                snap.body = buf
                snap.header = buf[:header_bytes]
                snap.sha256 = hashlib.sha256(buf).hexdigest()
            # rare race: file grew past cap between fstat and read
            if snap.body is not None and len(snap.body) != size:
                snap.changed = True
        st_after = os.fstat(fh.fileno())
    if st_before.st_size != st_after.st_size or \
            st_before.st_mtime_ns != st_after.st_mtime_ns:
        snap.changed = True
        if snap.body is not None and st_before.st_size != st_after.st_size:
            snap.body = None
            snap.header = snap.header or b""
            snap.sha256 = None
            snap.truncated = True
    return snap


def stream_file(path: Path, limit: int, chunk: int = 1024 * 1024):
    """Generator yielding up to ``limit`` bytes via a no-follow fd.
    Used by the ClamAV engine for bounded streaming."""
    fd = open_nofollow(path)
    with os.fdopen(fd, "rb", closefd=True) as fh:
        st = os.fstat(fh.fileno())
        if not statmod.S_ISREG(st.st_mode):
            raise OSError("not a regular file")
        remaining = min(limit, st.st_size)
        while remaining > 0:
            data = fh.read(min(chunk, remaining))
            if not data:
                break
            remaining -= len(data)
            yield data


def iter_walk(
    root: Path,
    max_depth: int,
    cancel: threading.Event,
    targets: Optional[list[str]] = None,
    on_dir_error: Optional[Callable[[str, str], None]] = None,
    liveness_probe: Optional[Callable[[], bool]] = None,
) -> Iterator[WalkEntry]:
    """Yield WalkEntry items. Directories are yielded before their contents.

    ``targets`` restricts traversal to explicit device-relative paths
    (custom scan).  Raises DeviceDisconnected / WalkCancelled.
    """
    root = Path(os.path.realpath(root))
    try:
        root_st = os.stat(root)
    except OSError as exc:
        raise DeviceDisconnected(f"device root {root} not accessible: {exc}") from exc
    root_dev = root_st.st_dev
    seen: set[tuple[int, int]] = set()
    stats = WalkStats()
    ops = 0

    def alive() -> bool:
        if cancel.is_set():
            raise WalkCancelled()
        nonlocal ops
        ops += 1
        if ops % 512 == 0:
            if liveness_probe is not None:
                if not liveness_probe():
                    raise DeviceDisconnected("device disappeared during scan")
            elif not os.path.isdir(root):
                raise DeviceDisconnected("device root no longer accessible")

    def walk_dir(dirpath: Path, rel: str, depth: int,
                 inherited_hidden: bool = False) -> Iterator[WalkEntry]:
        alive()
        try:
            st_dir = os.stat(dirpath)
        except FileNotFoundError as exc:
            if not os.path.isdir(root):
                raise DeviceDisconnected("device root no longer accessible") from exc
            if on_dir_error:
                on_dir_error(rel or ".", "directory vanished during scan")
            return
        except PermissionError:
            stats.dirs_failed += 1
            if on_dir_error:
                on_dir_error(rel or ".", "permission denied")
            return
        except OSError as exc:
            stats.dirs_failed += 1
            if on_dir_error:
                on_dir_error(rel or ".", f"unreadable directory: {exc.strerror or exc}")
            return

        key = (st_dir.st_dev, st_dir.st_ino)
        if key in seen:
            stats.loop_skips += 1
            return
        seen.add(key)

        try:
            with os.scandir(dirpath) as it:
                children = list(it)
        except PermissionError:
            stats.dirs_failed += 1
            if on_dir_error:
                on_dir_error(rel or ".", "permission denied")
            return
        except FileNotFoundError as exc:
            if not os.path.isdir(root):
                raise DeviceDisconnected("device root no longer accessible") from exc
            if on_dir_error:
                on_dir_error(rel or ".", "directory vanished during scan")
            return
        except OSError as exc:
            stats.dirs_failed += 1
            if on_dir_error:
                on_dir_error(rel or ".", f"cannot enumerate: {exc.strerror or exc}")
            return

        stats.dirs += 1
        dir_hidden = inherited_hidden or _is_hidden(dirpath.name, st_dir)
        yield WalkEntry(abspath=dirpath, rel=rel or ".", name=dirpath.name or rel,
                        kind="dir", hidden=dir_hidden,
                        system=_is_system_rel(rel or dirpath.name, st_dir), st=st_dir)

        if depth >= max_depth:
            if children:
                stats.depth_limited += len(children)
                if on_dir_error:
                    on_dir_error(rel or ".", f"directory depth limit ({max_depth}) reached; subtree skipped")
            return

        for entry in children:
            alive()
            name = entry.name
            child_rel = f"{rel}/{name}" if rel else name
            try:
                st = entry.stat(follow_symlinks=False)
            except FileNotFoundError:
                continue          # vanished between scandir and stat; harmless
            except PermissionError:
                stats.special += 1
                yield WalkEntry(abspath=dirpath / name, rel=child_rel, name=name,
                                kind="other",
                                hidden=dir_hidden or _is_hidden(name, None),
                                system=_is_system_rel(child_rel, None))
                continue
            except OSError:
                stats.special += 1
                continue

            hidden = dir_hidden or _is_hidden(name, st)   # hidden by inheritance
            system = _is_system_rel(child_rel, st)

            if statmod.S_ISLNK(st.st_mode):
                stats.symlinks += 1
                yield WalkEntry(abspath=dirpath / name, rel=child_rel, name=name,
                                kind="symlink", hidden=hidden, system=system,
                                size=0, mtime=st.st_mtime, st=st)
            elif statmod.S_ISREG(st.st_mode):
                stats.files += 1
                yield WalkEntry(abspath=dirpath / name, rel=child_rel, name=name,
                                kind="file", hidden=hidden, system=system,
                                size=st.st_size, mtime=st.st_mtime, st=st)
            elif statmod.S_ISDIR(st.st_mode):
                if st.st_dev != root_dev:
                    stats.mount_jail_skips += 1
                    if on_dir_error:
                        on_dir_error(child_rel, "different mount point; skipped (stays inside device volume)")
                    continue
                yield from walk_dir(Path(entry.path), child_rel, depth + 1,
                                    hidden)
            else:
                stats.special += 1
                yield WalkEntry(abspath=dirpath / name, rel=child_rel, name=name,
                                kind="other", hidden=hidden, system=system,
                                size=0, mtime=st.st_mtime, st=st)

    if targets:
        for t in targets:
            target, lst = validate_custom_target(root, t)
            if statmod.S_ISREG(lst.st_mode):
                yield WalkEntry(abspath=target, rel=t, name=target.name, kind="file",
                                hidden=_is_hidden(target.name, lst),
                                system=_is_system_rel(t, lst),
                                size=lst.st_size, mtime=lst.st_mtime, st=lst)
            else:
                yield from walk_dir(target, t, 0)
    else:
        yield from walk_dir(root, "", 0)

    iter_walk.last_stats = stats  # type: ignore[attr-defined]
