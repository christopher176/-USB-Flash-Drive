"""Removable-device detection.

An allowlist approach is used: only mounts that look genuinely removable
(USB-style filesystems, media mount points, explicit dev/demo roots) are ever
returned.  System volumes can therefore never be scanned, even by mistake.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

from .config import Settings
from .models import Device

USB_FILESYSTEMS = {
    "vfat", "fat", "fat32", "msdos", "exfat", "ntfs", "ntfs3", "hfsplus",
    "apfs", "udf", "iso9660", "f2fs", "btrfs", "ext2", "ext3", "ext4",
    "xfs",  # included only when mounted under media paths (see below)
}
MEDIA_PREFIXES = ("/media/", "/run/media/", "/mnt/", "/volumes/")
ALWAYS_REMOVABLE_FS = {"vfat", "fat", "fat32", "msdos", "exfat", "ntfs",
                       "ntfs3", "udf", "iso9660"}
SYSTEM_EXACT = {"/", "/boot", "/boot/efi", "/usr", "/etc", "/var", "/home",
                "/opt", "/root", "/srv", "/bin", "/sbin", "/lib", "/lib64",
                "/proc", "/sys", "/dev", "/run", "/tmp", "/snap"}
SYSTEM_PREFIXES = ("/system", "/private", "/users", "/applications",
                   "/library", "c:\\", "d:\\windows")


def _looks_system(mount_point: str) -> bool:
    mp = mount_point.rstrip("/").lower() or "/"
    if mp in SYSTEM_EXACT:
        return True
    return any(mp.startswith(p) for p in SYSTEM_PREFIXES)


def _device_id(mount_point: str, label: str) -> str:
    return hashlib.sha1(f"{mount_point}|{label}".encode()).hexdigest()[:16]


def _label_for(mount_point: str) -> str:
    name = Path(mount_point.rstrip("/")).name
    return name or mount_point


def _usage(mount_point: str) -> tuple[int, int, int]:
    try:
        u = shutil.disk_usage(mount_point)
        return u.total, u.used, u.free
    except OSError:
        return 0, 0, 0


def _list_mounts() -> list[tuple[str, str, str]]:
    """(device_node, mount_point, fs_type) — Linux/macOS via /proc or mount."""
    out: list[tuple[str, str, str]] = []
    proc = Path("/proc/mounts")
    if proc.exists():
        try:
            for line in proc.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    out.append((parts[0], parts[1].replace("\\040", " "), parts[2]))
        except OSError:
            pass
        return out
    try:
        proc_out = subprocess.run(["/bin/df"], capture_output=True, text=True,
                                  timeout=5).stdout  # minimal fallback
        for line in proc_out.splitlines()[1:]:
            p = line.split()
            if len(p) >= 6:
                out.append((p[0], p[-1], ""))
    except Exception:
        pass
    return out


def _windows_drives() -> list[tuple[str, str]]:
    """Windows: (root_path, kind) where kind is 'removable'/'fixed'."""
    out: list[tuple[str, str]] = []
    if sys.platform.startswith("win"):
        import ctypes
        try:
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            DRIVE_REMOVABLE = 2
            for i in range(26):
                if bitmask & (1 << i):
                    root = f"{chr(65 + i)}:\\"
                    dtype = ctypes.windll.kernel32.GetDriveTypeW(root)
                    out.append((root, "removable" if dtype == DRIVE_REMOVABLE else "fixed"))
        except Exception:
            pass
    return out


def list_devices(settings: Settings) -> list[Device]:
    """Enumerate scan-eligible devices.  Never includes system volumes."""
    devices: list[Device] = []
    seen: set[str] = set()

    if sys.platform.startswith("win"):
        for root, kind in _windows_drives():
            if kind != "removable" or _looks_system(root):
                continue
            total, used, free = _usage(root)
            label = _label_for(root.rstrip("\\")) or root
            devices.append(Device(id=_device_id(root, label), label=label,
                                  mount_point=root, fs_type="",
                                  total_bytes=total, used_bytes=used,
                                  free_bytes=free, kind="removable",
                                  available=os.path.exists(root)))
    else:
        for node, mp, fs in _list_mounts():
            if mp in seen or _looks_system(mp):
                continue
            fs = fs.lower()
            under_media = any(mp.startswith(p) for p in MEDIA_PREFIXES)
            eligible = (fs in ALWAYS_REMOVABLE_FS) or \
                       (under_media and fs in USB_FILESYSTEMS)
            if not eligible:
                continue
            seen.add(mp)
            label = _label_for(mp)
            total, used, free = _usage(mp)
            devices.append(Device(id=_device_id(mp, label), label=label,
                                  mount_point=mp, fs_type=fs,
                                  total_bytes=total, used_bytes=used,
                                  free_bytes=free, kind="removable",
                                  available=os.path.isdir(mp) and os.access(mp, os.R_OK),
                                  detail=node))

    # Explicitly-allowed extra roots (development/demo only, from env config)
    for extra in settings.extra_roots():
        mp = str(extra)
        if mp in seen or _looks_system(mp):
            continue
        seen.add(mp)
        label = _label_for(mp)
        total, used, free = _usage(mp)
        if extra.is_dir():
            used = _content_size(extra)
            total, free = used, 0     # capacity reflects synthetic content only
        devices.append(Device(id=_device_id(mp, label), label=label,
                              mount_point=mp, fs_type="demo",
                              total_bytes=total, used_bytes=used,
                              free_bytes=free, kind="demo",
                              available=extra.is_dir(),
                              detail="explicitly allowed development target"))
    return devices


def _content_size(root: Path, cap: int = 200_000) -> int:
    """Sum of regular-file sizes under root (bounded; used for demo roots)."""
    total = 0
    count = 0
    try:
        for dirpath, _dirs, files in os.walk(root):
            for name in files:
                count += 1
                if count > cap:
                    return total
                try:
                    total += os.lstat(os.path.join(dirpath, name)).st_size
                except OSError:
                    pass
    except OSError:
        pass
    return total


class DeviceRegistry:
    """Snapshot-with-refresh wrapper so scans can validate device ids."""

    def __init__(self, settings: Settings):
        self.settings = settings

    def list(self) -> list[Device]:
        return list_devices(self.settings)

    def get(self, device_id: str) -> Optional[Device]:
        for d in self.list():
            if d.id == device_id:
                return d
        return None

    def get_anywhere(self, device_id: str) -> Optional[Device]:
        """Find a device mount recorded in extra roots even if unmounted."""
        for extra in self.settings.extra_roots():
            label = _label_for(str(extra))
            if _device_id(str(extra), label) == device_id:
                total, used, free = _usage(str(extra))
                return Device(id=device_id, label=label, mount_point=str(extra),
                              fs_type="demo", total_bytes=total,
                              used_bytes=used, free_bytes=free, kind="demo",
                              available=extra.is_dir())
        return self.get(device_id)

    def is_accessible(self, device: Device) -> bool:
        try:
            if not os.path.isdir(device.mount_point):
                return False
            with os.scandir(device.mount_point) as it:
                next(it, None)
            return True
        except OSError:
            return False


def eject_device(device: Device) -> dict:
    """Best-effort safe eject. Never fails 'successfully' - reports the truth."""
    if device.kind == "demo":
        return {"ejected": False, "device_id": device.id,
                "message": "Demo/development targets cannot be ejected; "
                           "remove the directory instead."}
    mp = device.mount_point
    try:
        if sys.platform == "darwin":
            exe = shutil.which("diskutil")
            if exe:
                r = subprocess.run([exe, "eject", mp], capture_output=True,
                                   text=True, timeout=60)
                ok = r.returncode == 0 and not os.path.isdir(mp)
                return {"ejected": ok, "device_id": device.id,
                        "message": (r.stdout or r.stderr).strip()[:500]}
        elif sys.platform.startswith("linux"):
            udisks = shutil.which("udisksctl")
            node = device.detail or ""
            if udisks and node.startswith("/dev/"):
                subprocess.run([udisks, "unmount", "-b", node],
                               capture_output=True, text=True, timeout=60)
                subprocess.run([udisks, "power-off", "-b", node],
                               capture_output=True, text=True, timeout=60)
                ok = not os.path.isdir(mp) or not os.path.ismount(mp)
                return {"ejected": ok, "device_id": device.id,
                        "message": "Ejected and powered off." if ok else
                                   "Unmount attempted; verify the device before removal."}
            umount = shutil.which("umount")
            if umount:
                r = subprocess.run([umount, mp], capture_output=True,
                                   text=True, timeout=60)
                ok = r.returncode == 0
                return {"ejected": ok, "device_id": device.id,
                        "message": ("Unmounted. Safe to remove." if ok else
                                    f"umount failed: {(r.stderr or '').strip()[:300]}")}
        return {"ejected": False, "device_id": device.id,
                "message": "No supported eject mechanism on this host; "
                           "use your operating system's 'Eject' before removal."}
    except Exception as exc:
        return {"ejected": False, "device_id": device.id,
                "message": f"eject attempt failed: {exc!r}"[:300]}
