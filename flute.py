#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""
The Magic Flute — passive Wi-Fi and Bluetooth survey using Kismet.

Copyright (C) 2026 The Magic Flute contributors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

Portable Linux helper: detects radios and GPS, installs Kismet if needed,
and runs a receive-only collection. No injection, deauth, association,
pairing, or credential attacks.

Authorized use only. Typical run:

    sudo python3 flute.py --setup
    sudo python3 flute.py
"""

from __future__ import annotations

import argparse
import base64
import csv
import io
import grp
import http.cookiejar
import json
import os
import pwd
import re
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import termios
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


TOOL_NAME = "The Magic Flute"
TOOL_ID = "flute"

KISMET_HTTP_USER = "flute"
# Kismet hops continuously in monitor mode; this is dwell time, not a scan poll.
# 5 hops/sec = 200 ms per channel (Kismet's own default).
DEFAULT_HOP_RATE = 5
MIN_HOP_RATE = 1
MAX_HOP_RATE = 20
GPS_BAUDS = (4800, 9600, 38400, 115200)
GPS_TERMIO = {
    4800: termios.B4800,
    9600: termios.B9600,
    38400: termios.B38400,
    115200: termios.B115200,
}
NMEA_RE = re.compile(rb"\$(GP|GN|GL|GA)(RMC|GGA|GLL|VTG|GSA)")
SIRF_MAGIC = b"\xa0\xa2"
GPSD_PORT = 2947
# Switch SiRF ASCII/NMEA mode at 4800 8N1 (no-op if the unit is already binary-only).
PSRF_NMEA_4800 = b"$PSRF100,1,4800,8,1,0*0C\r\n"
USB_GPS_HINTS = {
    ("067b", "2303"): "GlobalSat BU-353S4 (Prolific PL2303 / SiRF Star IV)",
    ("1546", "01a7"): "u-blox GPS",
    ("1546", "01a8"): "u-blox GPS",
}
PANDA_USB_IDS = {("0e8d", "7961"), ("0e8d", "7612"), ("148f", "5370"), ("148f", "5572")}
NEEDED_GROUPS = ("kismet", "dialout")
MIN_PYTHON = (3, 9)
DEB_BASE_PACKAGES = [
    "iw",
    "rfkill",
    "usbutils",
    "iproute2",
    "wget",
    "gnupg",
    "ca-certificates",
    "gpsd",
    "gpsd-clients",
]
DEB_KISMET_PACKAGES = [
    "kismet",
    "kismet-capture-linux-wifi",
    "kismet-capture-linux-bluetooth",
]
DEB_PACKAGES = DEB_BASE_PACKAGES + DEB_KISMET_PACKAGES
KISMET_APT_KEY_URL = "https://www.kismetwireless.net/repos/kismet-release.gpg.key"
KISMET_APT_KEYRING = "/usr/share/keyrings/kismet-archive-keyring.gpg"
KISMET_APT_LIST = "/etc/apt/sources.list.d/kismet.list"
KISMET_APT_CODENAMES = {
    "kali",
    "bookworm",
    "trixie",
    "bionic",
    "focal",
    "jammy",
    "noble",
    "plucky",
    "resolute",
}
FEDORA_PACKAGES = ["kismet", "iw", "rfkill", "usbutils", "iproute", "gpsd", "gpsd-clients"]
ARCH_PACKAGES = ["kismet", "iw", "usbutils", "iproute2", "gpsd"]
IEEE_OUI_SOURCES = (
    ("https://standards-oui.ieee.org/oui/oui.csv", 24),
    ("https://standards-oui.ieee.org/oui28/mam.csv", 28),
    ("https://standards-oui.ieee.org/oui36/oui36.csv", 36),
)
IEEE_DB_NAME = "ieee_mac_vendors.csv"
IEEE_DB_MAX_AGE_DAYS = 180
HTTP_USER_AGENT = "The-Magic-Flute/1.0 (passive wireless survey; GPL-3.0-or-later)"
CAPTURE_BINS = (
    "kismet_cap_linux_wifi",
    "kismet_cap_linux_bluetooth",
)
NEEDED_CAPS = "cap_net_admin,cap_net_raw"

DISCLAIMER = """\
  AUTHORIZED USE ONLY
  The Magic Flute passively records Wi-Fi and Bluetooth emissions (MAC addresses,
  SSIDs, signal levels, advertised names) and can tag them with GPS.

  Run it only where you have legal authority — for example a signed Rules
  of Engagement, written client/owner permission, your own equipment and
  premises, or another lawful basis. Unauthorized interception of radio
  communications can be a crime. You are responsible for complying with
  local law. The authors assume no liability for misuse.

  Mode: receive-only. No packet injection, deauthentication, association,
  Bluetooth pairing, or credential attacks.
"""


class Colors:
    RED = "\033[31m"
    GRN = "\033[32m"
    YEL = "\033[33m"
    CYN = "\033[36m"
    BLD = "\033[1m"
    DIM = "\033[2m"
    RST = "\033[0m"

    enabled = sys.stdout.isatty()

    @classmethod
    def wrap(cls, color: str, text: str) -> str:
        if not cls.enabled:
            return text
        return f"{color}{text}{cls.RST}"


def log(msg: str, level: str = "info") -> None:
    palette = {
        "info": Colors.CYN,
        "ok": Colors.GRN,
        "warn": Colors.YEL,
        "err": Colors.RED,
        "hdr": Colors.BLD,
    }
    prefix = {
        "info": "[*]",
        "ok": "[+]",
        "warn": "[!]",
        "err": "[-]",
        "hdr": "[#]",
    }.get(level, "[*]")
    print(Colors.wrap(palette.get(level, Colors.CYN), f"{prefix} {msg}"))


def is_root() -> bool:
    return os.geteuid() == 0


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def iso_utc(ts: int | float | None) -> str:
    if not ts:
        return ""
    try:
        return datetime.fromtimestamp(int(ts), tz=timezone.utc).isoformat()
    except (OSError, OverflowError, ValueError):
        return str(ts)


def which_or_exit(name: str) -> str:
    path = shutil.which(name)
    if not path:
        log(f"{name} is not on PATH. Install it and retry.", "err")
        sys.exit(1)
    return path


def run_cmd(
    args: list[str],
    timeout: int = 15,
    env: dict[str, str] | None = None,
    stdin: str | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            args,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            input=stdin,
        )
    except FileNotFoundError:
        exe = args[0] if args else ""
        return subprocess.CompletedProcess(args, 127, "", f"{exe}: not found\n")


def kismet_version(kismet_bin: str) -> str:
    proc = run_cmd([kismet_bin, "--version"])
    line = (proc.stdout or proc.stderr or "").splitlines()
    return line[0].strip() if line else "unknown"


def sanitize_title(name: str) -> str:
    cleaned = re.sub(r"[^\w.\-]+", "_", name.strip(), flags=re.A)
    cleaned = re.sub(r"_+", "_", cleaned).strip("._-")
    return cleaned[:80] or "flute"


def port_open(host: str, port: int) -> bool:
    sock = socket.socket()
    sock.settimeout(0.4)
    try:
        sock.connect((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def read_sysfs(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def kg(obj: Any, *path: str, default: Any = "") -> Any:
    cur = obj
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return default if cur is None else cur


def valid_coord(lat: Any, lon: Any) -> bool:
    try:
        lat_f = float(lat)
        lon_f = float(lon)
    except (TypeError, ValueError):
        return False
    if lat_f == 0.0 and lon_f == 0.0:
        return False
    return -90.0 <= lat_f <= 90.0 and -180.0 <= lon_f <= 180.0


def fmt_coord(lat: Any, lon: Any) -> str:
    if not valid_coord(lat, lon):
        return ""
    return f"{float(lat):.6f},{float(lon):.6f}"


def print_banner() -> None:
    print(Colors.wrap(Colors.BLD, f"\n {TOOL_NAME}"))
    print(Colors.wrap(Colors.DIM, "  passive Wi-Fi / Bluetooth survey (Kismet)"))
    print(
        Colors.wrap(
            Colors.DIM,
            "  Copyright (C) 2026 The Magic Flute contributors. "
            "GPL-3.0-or-later; no warranty. See LICENSE.\n",
        )
    )
    print(Colors.wrap(Colors.YEL, DISCLAIMER))
    log("Purpose: find unexpected transmissions, unauthorized wireless devices,")
    log("         and authorized devices operating outside an allowed area.")
    log("Wi-Fi  : receive-only monitor mode (no inject, deauth, or association).")
    log(
        "Bluetooth: Kismet linuxbluetooth listens for BLE advertisements;"
        " classic discovery uses HCI inquiry and does not pair or connect."
    )


def confirm_roe(assume_yes: bool) -> None:
    if assume_yes:
        log("Authorization acknowledgement provided (--i-have-roe).", "ok")
        return
    if not sys.stdin.isatty():
        log(
            "No TTY. Re-run interactively, or pass --i-have-roe plus operator "
            "and adapter flags.",
            "err",
        )
        sys.exit(2)
    print()
    print(
        "Type YES to confirm you have a signed Rules of Engagement or other "
        "lawful written authorization for this collection."
    )
    answer = input("Authorization: ").strip()
    if answer.upper() != "YES":
        log("Aborted. No collection started.", "err")
        sys.exit(2)
    log("Authorization recorded.", "ok")


def ask_text(prompt: str, default: str = "", required: bool = True) -> str:
    if default:
        shown = f"{prompt} [{default}]: "
    else:
        shown = f"{prompt}: "
    if not sys.stdin.isatty():
        if default:
            return default
        log(f"No TTY and no value for: {prompt}", "err")
        sys.exit(2)
    while True:
        value = input(shown).strip()
        if not value:
            value = default
        if value or not required:
            return value
        print("  A value is required.")


def ask_yes_no(question: str, *, default: bool = False) -> bool:
    """Ask a yes/no question. Offline-safe default is no."""
    if not sys.stdin.isatty():
        return default
    suffix = " [Y/n]: " if default else " [y/N]: "
    raw = input(question + suffix).strip().lower()
    if not raw:
        return default
    if raw in {"y", "yes"}:
        return True
    if raw in {"n", "no"}:
        return False
    return default


def parse_hop_rate(raw: str) -> int:
    """Parse hops-per-second. Accepts '5', '5/sec', '5/s'."""
    text = (raw or "").strip().lower()
    text = text.replace("hops/sec", "/sec").replace("hops per second", "/sec")
    text = re.sub(r"\s+", "", text)
    match = re.fullmatch(r"(\d+(?:\.\d+)?)(?:/s(?:ec)?)?", text)
    if not match:
        raise ValueError(f"invalid hop rate {raw!r}")
    hops = int(round(float(match.group(1))))
    if hops < MIN_HOP_RATE or hops > MAX_HOP_RATE:
        raise ValueError(
            f"hop rate must be {MIN_HOP_RATE}-{MAX_HOP_RATE} hops/sec, not {hops}"
        )
    return hops


def hop_dwell_ms(hops: int) -> int:
    return int(round(1000.0 / hops))


def ask_hop_rate(default: int = DEFAULT_HOP_RATE) -> int:
    print()
    print("Wi-Fi channel hop rate (hops per second).")
    print("  Monitor mode is continuous; this is how often the radio changes channel.")
    print(f"  {default} = {hop_dwell_ms(default)} ms/channel (Kismet default, good for walking).")
    print("  Lower (1-2) dwells longer on each channel; higher (8-10) sweeps faster.")
    while True:
        raw = ask_text("Channel hop rate, hops/sec", default=str(default), required=True)
        try:
            return parse_hop_rate(raw)
        except ValueError as exc:
            print(f"  {exc}. Enter an integer {MIN_HOP_RATE}-{MAX_HOP_RATE}.")


def ask_choice(
    title: str,
    options: list[dict[str, Any]],
    *,
    allow_skip: bool = False,
    default_index: int = 0,
) -> dict[str, Any] | None:
    if not options:
        return None
    print()
    log(title, "hdr")
    for idx, opt in enumerate(options, start=1):
        mark = "  (recommended)" if opt.get("recommended") else ""
        print(f"  {idx}) {opt['label']}{mark}")
        for line in opt.get("detail") or []:
            print(f"      {line}")
    skip_hint = "/s=skip" if allow_skip else ""
    default_n = default_index + 1
    prompt = f"Select [1-{len(options)}{skip_hint}] (default {default_n}): "
    if not sys.stdin.isatty():
        return options[default_index]
    while True:
        raw = input(prompt).strip().lower()
        if not raw:
            return options[default_index]
        if allow_skip and raw in {"s", "skip", "none", "n"}:
            return None
        if raw.isdigit() and 1 <= int(raw) <= len(options):
            return options[int(raw) - 1]
        print("  Enter a listed number" + (" or s to skip." if allow_skip else "."))


def chown_tree(path: Path) -> None:
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user or not is_root():
        return
    try:
        info = pwd.getpwnam(sudo_user)
    except KeyError:
        return
    uid, gid = info.pw_uid, info.pw_gid
    for root, dirs, files in os.walk(path):
        os.chown(root, uid, gid)
        for name in dirs + files:
            try:
                os.chown(os.path.join(root, name), uid, gid)
            except OSError:
                pass


def real_username() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name


def os_release() -> dict[str, str]:
    info: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return info
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, val = line.split("=", 1)
        info[key] = val.strip().strip('"')
    return info


def user_group_names(username: str) -> set[str]:
    names: set[str] = set()
    try:
        pw = pwd.getpwnam(username)
    except KeyError:
        return names
    names.add(grp.getgrgid(pw.pw_gid).gr_name)
    try:
        extra = os.getgrouplist(username, pw.pw_gid)
    except (AttributeError, OSError):
        extra = []
        for entry in grp.getgrall():
            if username in entry.gr_mem:
                extra.append(entry.gr_gid)
    for gid in extra:
        try:
            names.add(grp.getgrgid(gid).gr_name)
        except KeyError:
            pass
    return names


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def binary_caps(path: str) -> str:
    getcap = shutil.which("getcap")
    if not getcap:
        return ""
    proc = run_cmd([getcap, path])
    text = (proc.stdout or "").strip()
    if " " in text:
        return text.split(" ", 1)[-1].replace("=", "").replace("+eip", "")
    return text


def has_needed_caps(path: str) -> bool:
    caps = binary_caps(path).replace(" ", "")
    return "cap_net_admin" in caps and "cap_net_raw" in caps


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    critical: bool = False
    fixable: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


def app_dir() -> Path:
    return Path(__file__).resolve().parent


def ieee_db_path() -> Path:
    return app_dir() / IEEE_DB_NAME


def ieee_db_age_days(path: Path | None = None) -> float | None:
    target = path or ieee_db_path()
    if not target.is_file() or target.stat().st_size == 0:
        return None
    age = time.time() - target.stat().st_mtime
    return age / 86400.0


def ieee_db_needs_refresh() -> bool:
    age = ieee_db_age_days()
    if age is None:
        return True
    return age > IEEE_DB_MAX_AGE_DAYS


def _http_get(url: str, timeout: int = 180) -> bytes:
    req = urllib.request.Request(
        url,
        headers={"User-Agent": HTTP_USER_AGENT, "Accept": "text/csv,text/plain,*/*"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_ieee_assignment_csv(raw: bytes, default_bits: int) -> list[tuple[str, str]]:
    text = raw.decode("utf-8-sig", errors="replace")
    reader = csv.reader(io.StringIO(text))
    header = next(reader, None)
    if not header:
        return []
    norm = [h.strip().lower() for h in header]
    assign_idx = 0
    name_idx = 1
    for i, col in enumerate(norm):
        if col in {"assignment", "oui", "macaddress", "mac address"}:
            assign_idx = i
        if col in {"organization name", "organization", "orgname", "vendor"}:
            name_idx = i
    rows: list[tuple[str, str]] = []
    for parts in reader:
        if len(parts) <= max(assign_idx, name_idx):
            continue
        assign = re.sub(r"[^0-9A-Fa-f]", "", parts[assign_idx]).upper()
        vendor = " ".join(parts[name_idx].split())
        if len(assign) < 6 or not vendor:
            continue
        rows.append((assign, vendor))
    _ = default_bits
    return rows


def download_ieee_oui_database(dest: Path) -> int:
    """Fetch MA-L / MA-M / MA-S CSVs from IEEE and write dest. Returns prefix count."""
    log("Downloading IEEE MAC vendor registries (MA-L, MA-M, MA-S)...")
    combined: dict[str, str] = {}
    for url, bits in IEEE_OUI_SOURCES:
        log(f"  {url}")
        raw = _http_get(url)
        parsed = _parse_ieee_assignment_csv(raw, bits)
        if not parsed:
            raise RuntimeError(f"IEEE registry at {url} parsed to zero rows")
        log(f"    {len(parsed)} assignments")
        for prefix, vendor in parsed:
            combined[prefix] = vendor
    tmp = dest.with_suffix(dest.suffix + ".partial")
    with tmp.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["prefix", "vendor"])
        for prefix in sorted(combined, key=lambda p: (len(p), p)):
            writer.writerow([prefix, combined[prefix]])
    os.replace(tmp, dest)
    size_mb = dest.stat().st_size / (1024 * 1024)
    log(
        f"IEEE vendor database: {len(combined)} prefixes, {size_mb:.1f} MiB -> {dest}",
        "ok",
    )
    return len(combined)


def ensure_ieee_oui_database(download: str = "ask") -> Path | None:
    """Offer to refresh the IEEE OUI table if missing or older than 180 days.

    download: "ask" (prompt; default no so offline hosts are safe),
              "yes" (always fetch), or "no" (never fetch).
    """
    path = ieee_db_path()
    age = ieee_db_age_days(path)
    if age is not None and age <= IEEE_DB_MAX_AGE_DAYS:
        size_mb = path.stat().st_size / (1024 * 1024)
        log(
            f"IEEE vendor database OK ({size_mb:.1f} MiB, {age:.0f} days old) -> {path}",
            "ok",
        )
        return path

    if age is None:
        reason = f"IEEE vendor database not found at {path}."
    else:
        reason = (
            f"IEEE vendor database is {age:.0f} days old "
            f"(limit {IEEE_DB_MAX_AGE_DAYS} days)."
        )
    log(reason, "warn")

    should_fetch = download == "yes"
    if download == "ask":
        if not sys.stdin.isatty():
            log(
                "No TTY: not downloading. Pass --download-ieee if you have "
                "internet, or --no-download-ieee to stay silent.",
                "warn",
            )
        else:
            print()
            print("A fresh copy is a few megabytes from standards-oui.ieee.org.")
            print("Skip this if this host has no internet; an existing file will be kept.")
            should_fetch = ask_yes_no("Download IEEE MAC vendor database now?", default=False)

    if not should_fetch:
        if path.is_file() and path.stat().st_size:
            log("Keeping the existing IEEE vendor database (no download).", "ok")
            return path
        log(
            "No IEEE vendor database on disk. ieee_manufacturer will be Unknown "
            "until you download one (re-run with network, or --download-ieee).",
            "warn",
        )
        return None

    try:
        download_ieee_oui_database(path)
        return path
    except Exception as exc:
        if path.is_file() and path.stat().st_size:
            log(f"IEEE download failed ({exc}); keeping the existing file.", "warn")
            return path
        log(
            f"IEEE download failed ({exc}). Manufacturer column will be Unknown.",
            "warn",
        )
        return None


def load_ieee_oui_table(path: Path | None = None) -> dict[str, str]:
    target = path or ieee_db_path()
    table: dict[str, str] = {}
    if not target.is_file():
        return table
    with target.open("r", encoding="utf-8", errors="replace", newline="") as handle:
        reader = csv.DictReader(handle)
        if not reader.fieldnames:
            return table
        fields = [f.strip().lower() for f in reader.fieldnames]
        if "prefix" in fields and "vendor" in fields:
            for row in reader:
                prefix = re.sub(r"[^0-9A-Fa-f]", "", row.get("prefix") or "").upper()
                vendor = (row.get("vendor") or "").strip()
                if prefix and vendor:
                    table[prefix] = vendor
            return table
    # Fallback: original IEEE CSV sitting on disk unused
    raw = target.read_bytes()
    for prefix, vendor in _parse_ieee_assignment_csv(raw, 24):
        table[prefix] = vendor
    return table


def lookup_ieee_manufacturer(mac: str, table: dict[str, str]) -> str:
    hexmac = re.sub(r"[^0-9A-Fa-f]", "", mac or "").upper()
    if len(hexmac) < 6 or not table:
        return "Unknown"
    for width in (9, 7, 6):
        if len(hexmac) >= width:
            vendor = table.get(hexmac[:width])
            if vendor:
                return vendor
    return "Unknown"


def apply_ieee_manufacturers(devices: list[dict[str, Any]], table: dict[str, str]) -> None:
    for rec in devices:
        rec["ieee_manufacturer"] = lookup_ieee_manufacturer(str(rec.get("mac") or ""), table)


def collect_checks() -> list[Check]:
    checks: list[Check] = []
    py_ok = sys.version_info >= MIN_PYTHON
    checks.append(
        Check(
            "python",
            py_ok,
            f"{sys.version.split()[0]} (need {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+)",
            critical=True,
        )
    )
    linux = sys.platform.startswith("linux")
    checks.append(Check("linux", linux, sys.platform, critical=True))

    for cmd, critical in (
        ("kismet", True),
        ("kismet_cap_linux_wifi", True),
        ("kismet_cap_linux_bluetooth", False),
        ("iw", True),
        ("rfkill", False),
    ):
        path = shutil.which(cmd)
        checks.append(
            Check(
                f"cmd:{cmd}",
                bool(path),
                path or "not on PATH",
                critical=critical,
                fixable=not path,
            )
        )

    for cap_bin in CAPTURE_BINS:
        path = shutil.which(cap_bin)
        if not path:
            continue
        ok = has_needed_caps(path) or is_root()
        detail = binary_caps(path) or ("root can capture without file caps" if is_root() else "missing cap_net_admin,cap_net_raw")
        if os.stat(path).st_mode & 0o4000:
            ok = True
            detail += " (setuid)"
        checks.append(
            Check(
                f"caps:{cap_bin}",
                ok,
                detail,
                critical=True,
                fixable=not ok,
            )
        )

    username = real_username()
    groups = user_group_names(username)
    for gname in NEEDED_GROUPS:
        exists = group_exists(gname)
        member = gname in groups
        if gname == "kismet" and not exists:
            checks.append(
                Check(
                    f"group:{gname}",
                    False,
                    "group does not exist yet (install Kismet)",
                    critical=False,
                    fixable=True,
                )
            )
            continue
        if gname == "dialout" and not exists:
            checks.append(
                Check(f"group:{gname}", True, "group not present on this OS", critical=False)
            )
            continue
        checks.append(
            Check(
                f"group:{gname}",
                member,
                f"{username} {'is' if member else 'is NOT'} a member",
                critical=False,
                fixable=not member,
            )
        )

    hard = []
    proc = run_cmd(["rfkill", "list"]) if shutil.which("rfkill") else None
    if proc:
        current = ""
        for line in (proc.stdout or "").splitlines():
            if re.match(r"^\d+:", line):
                current = line
            elif "Hard blocked: yes" in line:
                hard.append(current.strip() or "radio")
        checks.append(
            Check(
                "rfkill-hard",
                not hard,
                "none" if not hard else "hardware switch on: " + "; ".join(hard),
                critical=bool(hard),
            )
        )

    gps_nodes = sorted(Path("/dev").glob("ttyUSB*")) + sorted(Path("/dev").glob("ttyACM*"))
    if gps_nodes:
        readable = [str(n) for n in gps_nodes if os.access(n, os.R_OK)]
        checks.append(
            Check(
                "gps-access",
                bool(readable) or is_root(),
                (
                    "readable: " + ", ".join(readable)
                    if readable or is_root()
                    else f"{gps_nodes[0]} not readable (join dialout or run with sudo)"
                ),
                critical=False,
                fixable=not readable,
            )
        )
    else:
        checks.append(
            Check("gps-access", True, "no USB GPS attached (optional)", critical=False)
        )

    wifi = list_wifi_controllers()
    checks.append(
        Check(
            "wifi-radios",
            bool(wifi),
            ", ".join(w["iface"] for w in wifi) or "none found",
            critical=True,
        )
    )
    monitor = [w for w in wifi if w.get("monitor")]
    checks.append(
        Check(
            "monitor-mode",
            bool(monitor),
            ", ".join(w["iface"] for w in monitor) or "no advertised monitor-capable iface",
            critical=False,
        )
    )
    leftover = leftover_monitor_ifaces()
    checks.append(
        Check(
            "leftover-monitor",
            not leftover,
            "none" if not leftover else "present: " + ", ".join(leftover),
            critical=False,
            fixable=bool(leftover),
        )
    )
    oui = ieee_db_path()
    age = ieee_db_age_days(oui)
    if age is None:
        checks.append(
            Check(
                "ieee-oui",
                False,
                f"missing {oui.name} (will ask before downloading)",
                critical=False,
                fixable=True,
            )
        )
    elif age > IEEE_DB_MAX_AGE_DAYS:
        checks.append(
            Check(
                "ieee-oui",
                False,
                f"{oui.name} is {age:.0f} days old (limit {IEEE_DB_MAX_AGE_DAYS})",
                critical=False,
                fixable=True,
            )
        )
    else:
        size_mb = oui.stat().st_size / (1024 * 1024)
        checks.append(
            Check(
                "ieee-oui",
                True,
                f"{oui.name} {size_mb:.1f} MiB, {age:.0f} days old",
            )
        )
    return checks


def print_checks(checks: list[Check]) -> None:
    log("Environment check", "hdr")
    for item in checks:
        level = "ok" if item.ok else ("err" if item.critical else "warn")
        status = "PASS" if item.ok else ("FAIL" if item.critical else "WARN")
        log(f"{status:4}  {item.name:28} {item.detail}", level)


def pkg_install_plan() -> tuple[str, list[str]]:
    info = os_release()
    os_id = (info.get("ID") or "").lower()
    like = (info.get("ID_LIKE") or "").lower()
    if os_id in {"debian", "ubuntu", "linuxmint", "pop", "raspbian", "kali"} or "debian" in like:
        return "apt", DEB_PACKAGES
    if os_id in {"fedora", "rhel", "centos", "rocky", "almalinux"} or "fedora" in like or "rhel" in like:
        return "dnf", FEDORA_PACKAGES
    if os_id in {"arch", "manjaro", "endeavouros"} or "arch" in like:
        return "pacman", ARCH_PACKAGES
    return "", []


def debian_codename() -> str:
    info = os_release()
    os_id = (info.get("ID") or "").lower()
    if os_id == "kali":
        return "kali"
    return (info.get("UBUNTU_CODENAME") or info.get("VERSION_CODENAME") or "").lower()


def apt_package_known(name: str) -> bool:
    proc = run_cmd(["apt-cache", "show", name])
    return proc.returncode == 0 and "Package:" in (proc.stdout or "")


def _apt_env() -> dict[str, str]:
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    return env


def _apt_install(packages: list[str], env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return run_cmd(["apt-get", "install", "-y", *packages], timeout=600, env=env)


def write_kismet_apt_list(codename: str, channel: str) -> None:
    line = (
        f"deb [signed-by={KISMET_APT_KEYRING}] "
        f"https://www.kismetwireless.net/repos/apt/{channel}/{codename} "
        f"{codename} main\n"
    )
    Path(KISMET_APT_LIST).write_text(line, encoding="utf-8")


def ensure_kismet_apt_repo() -> bool:
    """Add the official Kismet apt repo. Distros like Pop!_OS/Ubuntu often omit Kismet."""
    if apt_package_known("kismet"):
        return True
    codename = debian_codename()
    if not codename:
        log("Could not determine distro codename for the Kismet apt repo.", "warn")
        return False
    if codename not in KISMET_APT_CODENAMES:
        log(
            f"No official Kismet apt repo listed for '{codename}'. "
            "See https://www.kismetwireless.net/packages/",
            "warn",
        )
        # Still try; new Ubuntu/Pop releases sometimes work with UBUNTU_CODENAME.

    log(f"Kismet is not in the distro repos. Adding official Kismet apt repo ({codename})...")
    _apt_install(["wget", "gnupg", "ca-certificates"], _apt_env())
    try:
        key = _http_get(KISMET_APT_KEY_URL, timeout=60)
    except Exception as exc:
        log(f"Could not download Kismet signing key: {exc}", "err")
        return False
    # Key is binary; run_cmd() is text-mode so call gpg directly.
    try:
        gpg_bin = subprocess.run(
            ["gpg", "--dearmor"],
            input=key,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except FileNotFoundError:
        log("gpg is not installed; cannot add the Kismet apt repo.", "err")
        return False
    if gpg_bin.returncode != 0 or not gpg_bin.stdout:
        log((gpg_bin.stderr or b"gpg --dearmor failed").decode("utf-8", "replace"), "err")
        return False
    keyring = Path(KISMET_APT_KEYRING)
    keyring.parent.mkdir(parents=True, exist_ok=True)
    keyring.write_bytes(gpg_bin.stdout)
    keyring.chmod(0o644)

    env = _apt_env()
    for channel in ("release", "git"):
        write_kismet_apt_list(codename, channel)
        log(f"Trying Kismet {channel} repo for {codename}...")
        upd = run_cmd(["apt-get", "update"], timeout=300, env=env)
        if upd.returncode != 0:
            err = (upd.stderr or upd.stdout or "").strip()
            log(err[:1500] or "apt-get update failed", "warn")
            continue
        if apt_package_known("kismet"):
            log(f"Kismet package is available from the {channel} repo.", "ok")
            return True
    log(
        "Added a Kismet source list but apt still cannot see the kismet package. "
        "See https://www.kismetwireless.net/packages/",
        "err",
    )
    return False


def install_packages() -> bool:
    manager, packages = pkg_install_plan()
    if not manager:
        log("Unknown distro. Install Kismet, iw, and rfkill from your package manager.", "err")
        return False
    if not is_root():
        log(f"Package install needs root. Re-run: sudo python3 {Path(sys.argv[0]).name} --setup", "err")
        return False
    log(f"Installing packages via {manager}: {' '.join(packages)}")
    try:
        if manager == "apt":
            env = _apt_env()
            for line in (
                "kismet kismet/install-setuid boolean true\n",
                "kismet-core kismet-core/install-setuid boolean true\n",
            ):
                run_cmd(["debconf-set-selections"], stdin=line, env=env)
            upd = run_cmd(["apt-get", "update"], timeout=300, env=env)
            if upd.returncode != 0:
                log((upd.stderr or upd.stdout or "apt-get update failed").strip(), "warn")
            base_ok = _apt_install(DEB_BASE_PACKAGES, env)
            if base_ok.returncode != 0:
                log(
                    (base_ok.stderr or base_ok.stdout or "base package install failed").strip()[:2000],
                    "warn",
                )
            else:
                log("Installed iw/rfkill/gpsd and helpers.", "ok")
            if not apt_package_known("kismet"):
                ensure_kismet_apt_repo()
            kismet_pkgs = [p for p in DEB_KISMET_PACKAGES if apt_package_known(p)]
            if "kismet" not in kismet_pkgs and apt_package_known("kismet"):
                kismet_pkgs.insert(0, "kismet")
            if not kismet_pkgs:
                log(
                    "Still cannot find a kismet package after adding the official repo. "
                    "Install from https://www.kismetwireless.net/packages/",
                    "err",
                )
                return shutil.which("iw") is not None and shutil.which("kismet") is not None
            proc = _apt_install(kismet_pkgs, env)
        elif manager == "dnf":
            proc = run_cmd(["dnf", "install", "-y", *packages], timeout=600)
        else:
            proc = run_cmd(["pacman", "-Sy", "--noconfirm", *packages], timeout=600)
    except subprocess.TimeoutExpired:
        log("Package install timed out.", "err")
        return False
    if proc.returncode != 0:
        log((proc.stderr or proc.stdout or "package install failed").strip()[:2000], "err")
        return shutil.which("kismet") is not None
    log("Packages installed.", "ok")
    return True


def ensure_groups(username: str) -> None:
    if not is_root():
        return
    for gname in NEEDED_GROUPS:
        if not group_exists(gname):
            log(f"Group {gname} not present; skipping.", "warn")
            continue
        if gname in user_group_names(username):
            log(f"{username} already in {gname}.", "ok")
            continue
        proc = run_cmd(["usermod", "-aG", gname, username])
        if proc.returncode == 0:
            log(f"Added {username} to {gname}. Log out and back in for this to take effect.", "ok")
        else:
            log((proc.stderr or f"usermod {gname} failed").strip(), "warn")


def ensure_capture_caps() -> None:
    if not is_root():
        return
    setcap = shutil.which("setcap")
    if not setcap:
        log("setcap not found; skipping capability repair.", "warn")
        return
    for name in CAPTURE_BINS:
        path = shutil.which(name)
        if not path:
            continue
        if has_needed_caps(path):
            log(f"{name} already has {NEEDED_CAPS}.", "ok")
            continue
        proc = run_cmd([setcap, f"{NEEDED_CAPS}+eip", path])
        if proc.returncode == 0:
            log(f"Set {NEEDED_CAPS} on {path}.", "ok")
        else:
            log((proc.stderr or f"setcap {name} failed").strip(), "warn")


def leftover_monitor_ifaces(phy: str = "") -> list[str]:
    """kismon* always; other monitor VAPs only when they sit on phy."""
    if not shutil.which("iw"):
        return []
    found: list[str] = []
    for row in parse_iw_dev():
        name = str(row.get("iface") or "")
        if not name:
            continue
        if name.startswith("kismon"):
            found.append(name)
            continue
        if row.get("type") == "monitor" and phy and row.get("phy") == phy:
            found.append(name)
    return found


def cleanup_monitor_vaps(phy: str = "") -> None:
    for name in leftover_monitor_ifaces(phy):
        log(f"Removing leftover monitor interface {name}.")
        proc = run_cmd(["iw", "dev", name, "del"])
        if proc.returncode != 0:
            log(
                f"Could not remove {name} (need root/net-admin). "
                f"Clean up with: sudo iw dev {name} del",
                "warn",
            )


def unblock_radios() -> None:
    if not shutil.which("rfkill"):
        return
    run_cmd(["rfkill", "unblock", "wifi"])
    run_cmd(["rfkill", "unblock", "wlan"])
    run_cmd(["rfkill", "unblock", "bluetooth"])
    log("Issued rfkill unblock for wifi and bluetooth.")


def prepare_system() -> list[str]:
    """Best-effort runtime fixes learned from field use. Returns blocking errors."""
    errors: list[str] = []
    if sys.version_info < MIN_PYTHON:
        errors.append(
            f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required "
            f"(this is {sys.version.split()[0]})."
        )
    if not shutil.which("kismet") or not shutil.which("kismet_cap_linux_wifi"):
        errors.append(
            f"Kismet is not installed. Run: sudo python3 {Path(sys.argv[0]).name} --setup"
        )
    if not shutil.which("iw"):
        errors.append("iw is not installed (needed to list and restore Wi-Fi interfaces).")

    unblock_radios()
    cleanup_monitor_vaps()

    proc = run_cmd(["rfkill", "list"]) if shutil.which("rfkill") else None
    if proc:
        block = ""
        current = ""
        for line in (proc.stdout or "").splitlines():
            if re.match(r"^\d+:", line):
                current = line
            if "Hard blocked: yes" in line:
                block += current.strip() + "; "
        if block:
            errors.append(
                "A radio is hardware-blocked (airplane/kill switch). "
                "Flip the switch and retry: " + block.strip("; ")
            )

    username = real_username()
    groups = user_group_names(username)
    if "kismet" in groups or is_root():
        pass
    elif group_exists("kismet"):
        log(
            f"{username} is not in the kismet group. Capture helpers may still work "
            f"via file capabilities. Prefer: sudo python3 {Path(sys.argv[0]).name} --setup",
            "warn",
        )
    if group_exists("dialout") and "dialout" not in groups and not is_root():
        log(
            f"{username} is not in dialout; USB GPS may be unreadable. "
            f"Fix with: sudo python3 {Path(sys.argv[0]).name} --setup  (then log out/in)",
            "warn",
        )
    return errors


def run_check(download_ieee: str = "ask") -> int:
    ensure_ieee_oui_database(download_ieee)
    checks = collect_checks()
    print_checks(checks)
    print_hardware(list_wifi_controllers(), list_bt_controllers(), list_gps_devices())
    critical = [c for c in checks if c.critical and not c.ok]
    if critical:
        log(
            f"{len(critical)} critical check(s) failed. "
            f"Run: sudo python3 {Path(sys.argv[0]).name} --setup",
            "err",
        )
        return 1
    log("Ready for a capture run (authorization still required).", "ok")
    return 0


def run_setup(download_ieee: str = "ask") -> int:
    print()
    log("Setup installs Kismet/capture helpers, adds your user to kismet and "
        "dialout, and sets capture capabilities.", "hdr")
    if not is_root():
        log(
            f"Re-run as root so packages and groups can be changed: "
            f"sudo python3 {Path(sys.argv[0]).name} --setup",
            "err",
        )
        print_checks(collect_checks())
        return 2
    username = real_username()
    if username == "root":
        log("Running as root with no SUDO_USER; groups will not be added to a login account.", "warn")
    ok = install_packages()
    ensure_groups(username)
    ensure_capture_caps()
    unblock_radios()
    cleanup_monitor_vaps()
    ensure_ieee_oui_database(download_ieee)
    print()
    print_checks(collect_checks())
    if not shutil.which("kismet"):
        log(
            "Kismet is still not on PATH. On Ubuntu/Pop!_OS it is not in the default "
            "repos; setup tried to add https://www.kismetwireless.net/packages/ . "
            "Install it from that page if apt still cannot find it.",
            "err",
        )
        return 1
    log("Setup finished.", "ok")
    log(
        "If you were added to kismet or dialout, log out and back in (or reboot) "
        "before capturing without sudo."
    )
    log(f"Then run: sudo python3 {Path(sys.argv[0]).name}")
    return 0


def usb_ids_from_sysfs(start: Path) -> tuple[str, str, str]:
    """Walk the resolved sysfs device path (not the class symlink parents)."""
    try:
        cur = start.resolve()
    except OSError:
        return "", "", ""
    for _ in range(12):
        vendor = read_sysfs(cur / "idVendor").lower()
        product = read_sysfs(cur / "idProduct").lower()
        if vendor and product and vendor != "1d6b":
            manuf = read_sysfs(cur / "manufacturer")
            prod = read_sysfs(cur / "product")
            label = " ".join(x for x in (manuf, prod) if x)
            return vendor, product, label
        if cur.parent == cur:
            break
        cur = cur.parent
    return "", "", ""


def usb_ids_for_net(iface: str) -> tuple[str, str]:
    vendor, product, _label = usb_ids_from_sysfs(Path(f"/sys/class/net/{iface}/device"))
    return vendor, product


def usb_ids_for_tty(devname: str) -> tuple[str, str, str]:
    return usb_ids_from_sysfs(Path(f"/sys/class/tty/{devname}/device"))


def net_driver(iface: str) -> str:
    link = Path(f"/sys/class/net/{iface}/device/driver")
    try:
        return link.resolve().name
    except OSError:
        return ""


def net_mac(iface: str) -> str:
    return read_sysfs(Path(f"/sys/class/net/{iface}/address")).upper()


def rfkill_state(kind: str, ident: str) -> str:
    proc = run_cmd(["rfkill", "-J"])
    if proc.returncode == 0 and proc.stdout.strip().startswith("{"):
        try:
            payload = json.loads(proc.stdout)
            rows = payload.get("") or payload.get("rfkilldevices") or []
            if isinstance(payload, dict) and not rows:
                for value in payload.values():
                    if isinstance(value, list):
                        rows = value
                        break
            for row in rows:
                if not isinstance(row, dict):
                    continue
                name = str(row.get("device") or row.get("name") or "")
                rtype = str(row.get("type") or "")
                if ident and ident not in name and ident != rtype:
                    continue
                if kind and rtype and kind not in rtype:
                    continue
                soft = str(row.get("soft") or "").lower()
                hard = str(row.get("hard") or "").lower()
                if hard in {"blocked", "1", "true"}:
                    return "hard-blocked"
                if soft in {"blocked", "1", "true"}:
                    return "soft-blocked"
                return "unblocked"
        except json.JSONDecodeError:
            pass
    proc = run_cmd(["rfkill", "list"])
    block = ""
    current = ""
    for line in (proc.stdout or "").splitlines():
        if re.match(r"^\d+:", line):
            if current:
                if ident.lower() in current.lower() or kind.lower() in current.lower():
                    block = current
            current = line.lower()
        else:
            current += " " + line.lower()
    if ident.lower() in current.lower() or (kind.lower() in current.lower() and not block):
        block = current
    if "hard blocked: yes" in block:
        return "hard-blocked"
    if "soft blocked: yes" in block:
        return "soft-blocked"
    if block:
        return "unblocked"
    return "unknown"


def phy_caps(phy: str) -> dict[str, Any]:
    if not phy or not shutil.which("iw"):
        return {"modes": [], "monitor": False, "bands": []}
    proc = run_cmd(["iw", "phy", phy, "info"])
    text = proc.stdout or ""
    modes: list[str] = []
    in_modes = False
    freqs: list[float] = []
    for line in text.splitlines():
        if "Supported interface modes:" in line:
            in_modes = True
            continue
        if in_modes:
            stripped = line.strip()
            if stripped.startswith("* "):
                mode = stripped[2:].strip()
                if ":" not in mode and "#{" not in mode:
                    modes.append(mode)
            elif stripped:
                in_modes = False
        match = re.search(r"\*\s+(\d+(?:\.\d+)?)\s+MHz", line)
        if match:
            freqs.append(float(match.group(1)))
    bands = []
    if any(f < 3000 for f in freqs):
        bands.append("2.4 GHz")
    if any(5000 <= f < 5900 for f in freqs):
        bands.append("5 GHz")
    if any(f >= 5900 for f in freqs):
        bands.append("6 GHz")
    return {
        "modes": modes,
        "monitor": "monitor" in modes,
        "bands": bands,
    }


def parse_iw_dev() -> list[dict[str, Any]]:
    if not shutil.which("iw"):
        return []
    proc = run_cmd(["iw", "dev"])
    ifaces: list[dict[str, Any]] = []
    phy = ""
    current: dict[str, Any] | None = None
    for line in (proc.stdout or "").splitlines():
        phy_match = re.match(r"^phy#(\d+)", line)
        if phy_match:
            phy = f"phy{phy_match.group(1)}"
            continue
        if_match = re.search(r"Interface\s+(\S+)", line)
        if if_match:
            if current:
                ifaces.append(current)
            current = {
                "iface": if_match.group(1),
                "phy": phy,
                "mac": "",
                "type": "",
            }
            continue
        if current is None:
            continue
        addr = re.search(r"addr\s+([0-9a-fA-F:]{11,})", line)
        if addr:
            current["mac"] = addr.group(1).upper()
        typ = re.search(r"type\s+(\S+)", line)
        if typ:
            current["type"] = typ.group(1)
    if current:
        ifaces.append(current)
    return ifaces


def kismet_wifi_list() -> list[tuple[str, str]]:
    proc = run_cmd(["kismet_cap_linux_wifi", "--list"])
    found: list[tuple[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        match = re.match(r"\s+(\S+)\s+\(([^)]+)\)", line)
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def kismet_bt_list() -> list[tuple[str, str]]:
    proc = run_cmd(["kismet_cap_linux_bluetooth", "--list"])
    found: list[tuple[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        match = re.match(r"\s+(\S+)\s+\(([^)]+)\)", line)
        if match:
            found.append((match.group(1), match.group(2)))
    return found


def is_usb_net(iface: str) -> bool:
    try:
        resolved = str(Path(f"/sys/class/net/{iface}/device").resolve())
    except OSError:
        return False
    return "/usb" in resolved


def classify_wifi(iface: str, driver: str, vendor: str, product: str) -> tuple[str, bool]:
    vid_pid = (vendor, product)
    if vid_pid in PANDA_USB_IDS or driver in {"mt7921u", "mt76x2u", "rt2800usb"}:
        return "Panda USB / MediaTek (preferred survey adapter)", True
    if driver == "iwlwifi":
        return "Built-in Intel Wi-Fi", False
    if iface.startswith("wlx") or is_usb_net(iface):
        return "USB Wi-Fi adapter", True
    return driver or "Wi-Fi adapter", False


def list_wifi_controllers() -> list[dict[str, Any]]:
    cap = {iface: driver for iface, driver in kismet_wifi_list()}
    seen: dict[str, dict[str, Any]] = {}
    for row in parse_iw_dev():
        iface = row["iface"]
        if iface.startswith("lo") or iface.startswith("docker"):
            continue
        if iface.startswith("kismon") or row.get("type") == "monitor":
            continue
        driver = cap.get(iface) or net_driver(iface)
        vendor, product = usb_ids_for_net(iface)
        hint, recommended = classify_wifi(iface, driver, vendor, product)
        caps = phy_caps(row.get("phy") or "")
        kill = rfkill_state("wlan", row.get("phy") or iface)
        usb = f"{vendor}:{product}" if vendor else ("usb" if is_usb_net(iface) else "pci/built-in")
        seen[iface] = {
            "kind": "wifi",
            "iface": iface,
            "phy": row.get("phy") or "",
            "mac": row.get("mac") or net_mac(iface),
            "driver": driver,
            "type": row.get("type") or "",
            "usb": usb,
            "hint": hint,
            "recommended": recommended,
            "monitor": bool(caps.get("monitor")),
            "bands": caps.get("bands") or [],
            "rfkill": kill,
            "label": f"{iface}  {hint}",
            "detail": [
                f"phy={row.get('phy') or '-'}  mac={row.get('mac') or net_mac(iface) or '-'}  "
                f"driver={driver or '-'}  bus={usb}",
                f"mode={row.get('type') or '-'}  monitor={'yes' if caps.get('monitor') else 'NO'}  "
                f"bands={', '.join(caps.get('bands') or ['unknown'])}  rfkill={kill}",
            ],
        }
    for iface, driver in cap.items():
        if iface not in seen:
            seen[iface] = {
                "kind": "wifi",
                "iface": iface,
                "phy": "",
                "mac": net_mac(iface),
                "driver": driver,
                "type": "",
                "usb": "",
                "hint": driver,
                "recommended": False,
                "monitor": True,
                "bands": [],
                "rfkill": "unknown",
                "label": f"{iface}  {driver}",
                "detail": [f"Reported by kismet_cap_linux_wifi ({driver})"],
            }
    items = list(seen.values())
    items.sort(key=lambda x: (not x.get("recommended"), x["iface"]))
    return items


def list_bt_controllers() -> list[dict[str, Any]]:
    cap = {iface: driver for iface, driver in kismet_bt_list()}
    items: list[dict[str, Any]] = []
    proc = run_cmd(["bluetoothctl", "list"])
    listed: dict[str, str] = {}
    for line in (proc.stdout or "").splitlines():
        match = re.search(
            r"Controller\s+([0-9A-Fa-f:]{17})\s+(\S+)(?:\s+\[([^\]]+)\])?", line
        )
        if match:
            listed[match.group(1).upper()] = match.group(2)

    hci_info: dict[str, dict[str, str]] = {}
    current_hci = ""
    hci_proc = run_cmd(["hciconfig", "-a"])
    for line in (hci_proc.stdout or "").splitlines():
        head = re.match(r"^(hci\d+):", line)
        if head:
            current_hci = head.group(1)
            hci_info[current_hci] = {}
            continue
        if not current_hci:
            continue
        addr = re.search(r"BD Address:\s+([0-9A-Fa-f:]{17})", line)
        if addr:
            hci_info[current_hci]["mac"] = addr.group(1).upper()
        if "Name:" in line:
            hci_info[current_hci]["name"] = line.split(":", 1)[-1].strip().strip("'\"")
        if "Manufacturer:" in line:
            hci_info[current_hci]["manuf"] = line.split(":", 1)[-1].strip()
        if line.strip().startswith("UP ") or "RUNNING" in line:
            hci_info[current_hci]["powered"] = "yes"

    hci_dirs = sorted(Path("/sys/class/bluetooth").glob("hci*"))
    names = [p.name for p in hci_dirs] or list(cap.keys()) or list(hci_info.keys())
    if not names:
        for iface, driver in cap.items():
            items.append(
                {
                    "kind": "bluetooth",
                    "iface": iface,
                    "mac": "",
                    "name": "",
                    "driver": driver,
                    "label": f"{iface}  {driver}",
                    "detail": ["Reported by kismet_cap_linux_bluetooth"],
                    "recommended": True,
                    "rfkill": rfkill_state("bluetooth", iface),
                }
            )
        return items

    for iface in names:
        info = hci_info.get(iface, {})
        mac = info.get("mac") or ""
        name = info.get("name") or listed.get(mac, "")
        manuf = info.get("manuf") or ""
        show = run_cmd(["bluetoothctl", "show", mac] if mac else ["bluetoothctl", "show"])
        for line in (show.stdout or "").splitlines():
            if "Manufacturer:" in line and not manuf:
                manuf = line.split(":", 1)[-1].strip()
            if line.strip().startswith("Name:") and not name:
                name = line.split(":", 1)[-1].strip()
        kill = rfkill_state("bluetooth", iface)
        powered = info.get("powered") or "unknown"
        usb_vendor, usb_product, usb_label = usb_ids_from_sysfs(
            Path(f"/sys/class/bluetooth/{iface}/device")
        )
        intel = (
            "Intel" in manuf
            or manuf.startswith("0x0002")
            or (usb_vendor, usb_product) == ("8087", "0033")
        )
        hint = "Built-in Intel Bluetooth" if intel else (manuf or usb_label or "Bluetooth controller")
        items.append(
            {
                "kind": "bluetooth",
                "iface": iface,
                "mac": mac,
                "name": name,
                "driver": cap.get(iface, "linuxhci"),
                "manuf": manuf,
                "label": f"{iface}  {hint}" + (f"  ({name})" if name else ""),
                "detail": [
                    f"bdaddr={mac or '-'}  manufacturer={manuf or usb_label or '-'}  "
                    f"usb={usb_vendor}:{usb_product if usb_product else '-'}  "
                    f"powered={powered}  rfkill={kill}",
                ],
                "recommended": True,
                "rfkill": kill,
            }
        )
    for iface, driver in cap.items():
        if not any(x["iface"] == iface for x in items):
            items.append(
                {
                    "kind": "bluetooth",
                    "iface": iface,
                    "mac": "",
                    "name": "",
                    "driver": driver,
                    "label": f"{iface}  {driver}",
                    "detail": ["Reported by kismet_cap_linux_bluetooth"],
                    "recommended": False,
                    "rfkill": "unknown",
                }
            )
    return items


def _set_serial(fd: int, baud: int) -> None:
    attrs = termios.tcgetattr(fd)
    attrs[0] = termios.IGNPAR
    attrs[1] = 0
    attrs[2] = termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[3] = 0
    speed = GPS_TERMIO[baud]
    attrs[4] = speed
    attrs[5] = speed
    termios.tcsetattr(fd, termios.TCSANOW, attrs)
    termios.tcflush(fd, termios.TCIFLUSH)


def read_serial_sample(device: Path, baud: int, seconds: float = 2.0) -> bytes:
    fd = -1
    try:
        fd = os.open(str(device), os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
        _set_serial(fd, baud)
        deadline = time.time() + seconds
        buf = b""
        while time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.3)
            if not ready:
                continue
            try:
                chunk = os.read(fd, 512)
            except BlockingIOError:
                continue
            if chunk:
                buf += chunk
        return buf
    except OSError:
        return b""
    finally:
        if fd >= 0:
            os.close(fd)


def classify_gps_bytes(buf: bytes) -> str:
    if not buf:
        return "silent"
    if NMEA_RE.search(buf):
        return "nmea"
    if SIRF_MAGIC in buf:
        return "sirf"
    nonprint = sum(1 for b in buf if b < 32 and b not in (9, 10, 13))
    if buf and nonprint / max(len(buf), 1) > 0.3:
        return "binary"
    return "noise"


def nmea_preview(buf: bytes) -> str:
    text = buf.decode("ascii", errors="replace")
    for line in text.splitlines():
        if line.startswith("$"):
            return line.strip()
    return "NMEA detected"


def probe_gps_device(device: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "mode": "silent",
        "baud": 4800,
        "sample": "",
        "buf": b"",
    }
    if not (os.access(device, os.R_OK) or is_root()):
        return result
    for baud in GPS_BAUDS:
        buf = read_serial_sample(device, baud, seconds=1.6)
        mode = classify_gps_bytes(buf)
        if mode == "silent":
            continue
        result["mode"] = mode
        result["baud"] = baud
        result["buf"] = buf
        result["sample"] = nmea_preview(buf) if mode == "nmea" else f"{mode} ({len(buf)} bytes @ {baud})"
        if mode in {"nmea", "sirf", "binary"}:
            return result
    return result


def try_sirf_to_nmea(device: Path, baud: int) -> bool:
    """Ask a SiRF unit already speaking ASCII to emit NMEA. Binary SiRF needs gpsd."""
    fd = -1
    try:
        fd = os.open(str(device), os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        _set_serial(fd, baud)
        os.write(fd, PSRF_NMEA_4800)
        time.sleep(0.4)
        return True
    except OSError:
        return False
    finally:
        if fd >= 0:
            os.close(fd)


def gpsd_listening() -> bool:
    return port_open("127.0.0.1", GPSD_PORT)


def gpsd_rpc(commands: list[bytes], wait: float = 2.0) -> list[dict[str, Any]]:
    """Talk JSON to gpsd. systemd gpsd.socket often listens with zero devices."""
    try:
        sock = socket.create_connection(("127.0.0.1", GPSD_PORT), 2)
    except OSError:
        return []
    sock.settimeout(wait)
    try:
        for cmd in commands:
            if not cmd.endswith(b"\n"):
                cmd += b"\n"
            sock.sendall(cmd)
        deadline = time.time() + wait
        buf = b""
        while time.time() < deadline:
            try:
                chunk = sock.recv(8192)
            except (TimeoutError, socket.timeout):
                break
            if not chunk:
                break
            buf += chunk
    except OSError:
        buf = b""
    finally:
        try:
            sock.close()
        except OSError:
            pass
    msgs: list[dict[str, Any]] = []
    for line in buf.decode("utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msgs.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return msgs


def gpsd_attached_paths() -> list[str]:
    paths: list[str] = []
    for msg in gpsd_rpc([b'?WATCH={"enable":true,"json":true};']):
        if msg.get("class") != "DEVICES":
            continue
        for dev in msg.get("devices") or []:
            if isinstance(dev, dict) and dev.get("path"):
                paths.append(str(dev["path"]))
    return paths


def gpsd_live_fix() -> dict[str, Any]:
    """Read TPV/SKY from gpsd so the live line is not stuck on Kismet's 0,0."""
    out: dict[str, Any] = {
        "valid": False,
        "connected": False,
        "sats": 0,
        "mode": 0,
    }
    for msg in gpsd_rpc([b'?WATCH={"enable":true,"json":true};'], wait=1.4):
        cls = msg.get("class")
        if cls == "DEVICES":
            out["connected"] = bool(msg.get("devices"))
        elif cls == "SKY":
            sats = msg.get("uSat")
            if sats is None:
                sats = msg.get("nSat")
            if sats is None:
                sats = len(msg.get("satellites") or [])
            try:
                out["sats"] = int(sats)
            except (TypeError, ValueError):
                pass
        elif cls == "TPV":
            out["connected"] = True
            try:
                mode = int(msg.get("mode") or 0)
            except (TypeError, ValueError):
                mode = 0
            out["mode"] = mode
            lat, lon = msg.get("lat"), msg.get("lon")
            if mode >= 2 and valid_coord(lat, lon):
                out["valid"] = True
                out["lat"] = float(lat)
                out["lon"] = float(lon)
                if msg.get("alt") is not None:
                    out["alt"] = msg.get("alt")
                out["fix"] = f"{mode}D"
    return out


def gpsd_add_device(device: str) -> bool:
    ctl = shutil.which("gpsdctl")
    if ctl:
        proc = run_cmd([ctl, "add", device])
        if proc.returncode == 0:
            log(f"Attached {device} to gpsd via gpsdctl.", "ok")
            return True
        err = (proc.stderr or proc.stdout or "").strip()
        if err:
            log(f"gpsdctl add: {err}", "warn")
    # JSON fallback
    path_json = json.dumps({"class": "DEVICE", "path": device})
    gpsd_rpc([f"?DEVICE={path_json};".encode()], wait=1.0)
    time.sleep(0.4)
    return any(p == device or Path(p).resolve() == Path(device).resolve() for p in gpsd_attached_paths())


def start_gpsd(device: str) -> subprocess.Popen[bytes] | None:
    """Make sure gpsd is actually reading this USB GPS, not an empty systemd socket."""
    gpsd = shutil.which("gpsd")
    if not gpsd:
        return None

    if gpsd_listening():
        attached = gpsd_attached_paths()
        if any(Path(p).name == Path(device).name for p in attached):
            log(f"gpsd already has {device}: {attached}", "ok")
            return None
        log(
            "gpsd port 2947 is open (often systemd gpsd.socket) but has no GPS "
            f"device {attached or '[]'}. Attaching {device}."
        )
        if gpsd_add_device(device):
            return None
        if is_root():
            log("Stopping empty systemd gpsd so we can bind the USB receiver.", "warn")
            run_cmd(["systemctl", "stop", "gpsd.socket", "gpsd.service"])
            time.sleep(0.4)

    log(f"Starting gpsd on {device} (SiRF/NMEA USB GPS).")
    proc = subprocess.Popen(
        [gpsd, "-N", "-n", "-D", "0", device],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )
    for _ in range(24):
        time.sleep(0.25)
        if gpsd_listening() and any(
            Path(p).name == Path(device).name for p in gpsd_attached_paths()
        ):
            log(f"gpsd is up (pid {proc.pid}) with {device}.", "ok")
            return proc
        if proc.poll() is not None:
            break
    log("gpsd did not attach the GPS on port 2947.", "warn")
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except OSError:
            proc.terminate()
    return None


def stop_gpsd(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except OSError:
        proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            proc.kill()


def configure_gps_backend(
    gps: dict[str, Any],
    *,
    start_daemon: bool = True,
) -> tuple[str, subprocess.Popen[bytes] | None]:
    """Pick Kismet serial NMEA vs gpsd. BU-353S4 often speaks SiRF binary, not NMEA."""
    device = Path(gps["device"])
    baud = int(gps.get("baud") or 4800)
    probe = probe_gps_device(device)
    mode = probe.get("mode") or "silent"
    if probe.get("baud"):
        baud = int(probe["baud"])
        gps["baud"] = baud
    gps["mode"] = mode
    log(f"GPS {device} probe: {mode} @ {baud} baud" + (f"  {probe.get('sample')}" if probe.get("sample") else ""))

    # Prefer gpsd for USB pucks. systemd gpsd.socket often listens with ZERO
    # devices; Kismet then shows "connected, searching" forever. Always attach
    # this tty. BU-353S4 SiRF binary also requires gpsd (not Kismet serial).
    if shutil.which("gpsd"):
        if mode in {"sirf", "binary"}:
            log(
                "This GPS is sending SiRF/binary, not NMEA. Using gpsd "
                "(required for GlobalSat BU-353S4 / SiRF Star IV).",
                "warn",
            )
        name = sanitize_title(gps.get("hint") or "gpsd")
        line = f"gps=gpsd:host=localhost,port={GPSD_PORT},name={name},reconnect=true"
        if not start_daemon:
            return line, None
        proc = start_gpsd(str(device))
        attached = any(Path(p).name == device.name for p in gpsd_attached_paths())
        if gpsd_listening() and (attached or proc is not None):
            gps["backend"] = "gpsd"
            return line, proc
        log("gpsd did not take the USB GPS; trying Kismet serial as a fallback.", "warn")

    if mode == "nmea":
        gps["backend"] = "serial"
        return (
            f"gps=serial:device={device},name={sanitize_title(gps.get('hint') or 'gps')},"
            f"baud={baud},reconnect=true"
        ), None

    if mode in {"sirf", "binary", "noise", "silent"}:
        if not shutil.which("gpsd"):
            log(
                "gpsd is not available. Install it with: "
                f"sudo python3 {Path(sys.argv[0]).name} --setup",
                "err",
            )
        if mode != "nmea" and try_sirf_to_nmea(device, baud):
            time.sleep(1)
            again = probe_gps_device(device)
            if again.get("mode") == "nmea":
                log("GPS switched to NMEA after PSRF100; using Kismet serial driver.", "ok")
                gps["mode"] = "nmea"
                return (
                    f"gps=serial:device={device},name={sanitize_title(gps.get('hint') or 'gps')},"
                    f"baud={again.get('baud') or baud},reconnect=true"
                ), None
        log(
            "Falling back to Kismet serial GPS. A SiRF-binary puck will stay at "
            "no-fix until gpsd is installed.",
            "warn",
        )
        return (
            f"gps=serial:device={device},name={sanitize_title(gps.get('hint') or 'gps')},"
            f"baud={baud},reconnect=true"
        ), None
    return "", None


def list_gps_devices() -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    nodes = sorted(Path("/dev").glob("ttyUSB*")) + sorted(Path("/dev").glob("ttyACM*"))
    for node in nodes:
        vendor, product, usb_label = usb_ids_for_tty(node.name)
        hint = USB_GPS_HINTS.get((vendor, product), usb_label or "USB serial device")
        if (vendor, product) == ("067b", "2303"):
            hint = "GlobalSat BU-353S4 (Prolific PL2303 / SiRF Star IV)"
        probe: dict[str, Any] = {"mode": "unreadable", "baud": 4800, "sample": ""}
        if os.access(node, os.R_OK) or is_root():
            probe = probe_gps_device(node)
        mode = probe.get("mode") or "unreadable"
        baud_hit = int(probe.get("baud") or 0)
        sample = str(probe.get("sample") or "")
        if mode == "unreadable":
            proto = "need dialout group or sudo to sample"
        elif mode == "silent":
            proto = "no data yet (waiting for receiver)"
        elif mode == "nmea":
            proto = "NMEA: " + sample[:60]
        elif mode in {"sirf", "binary"}:
            proto = f"{mode} — Kismet needs gpsd for this unit"
        else:
            proto = mode
        found.append(
            {
                "device": str(node),
                "vendor": vendor,
                "product": product,
                "hint": hint,
                "baud": baud_hit or 4800,
                "mode": mode,
                "nmea": sample if mode == "nmea" else "",
                "label": f"{node}  {hint}",
                "detail": [
                    f"usb={vendor}:{product or '-'}  baud={baud_hit or 4800}  {proto}"
                ],
                "recommended": (vendor, product) == ("067b", "2303") or mode in {"nmea", "sirf", "binary"},
            }
        )
    found.sort(key=lambda x: (not x.get("recommended"), x["device"]))
    return found


def nm_set_managed(iface: str, managed: bool) -> None:
    nmcli = shutil.which("nmcli")
    if not nmcli:
        return
    flag = "yes" if managed else "no"
    proc = run_cmd([nmcli, "device", "set", iface, "managed", flag])
    if proc.returncode == 0:
        log(f"NetworkManager managed={flag} on {iface}.")
    else:
        err = (proc.stderr or proc.stdout or "").strip()
        if err:
            log(f"nmcli: {err}", "warn")


def restore_wifi(iface: str) -> None:
    target_phy = ""
    for row in parse_iw_dev():
        if row.get("iface") == iface:
            target_phy = str(row.get("phy") or "")
            break
    cleanup_monitor_vaps(target_phy)
    run_cmd(["iw", "dev", iface, "set", "type", "managed"])
    run_cmd(["ip", "link", "set", iface, "up"])
    nm_set_managed(iface, True)


class KismetClient:
    def __init__(self, base: str, username: str, password: str) -> None:
        self.base = base.rstrip("/")
        self.username = username
        self.password = password
        jar = http.cookiejar.CookieJar()
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, self.base, username, password)
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(jar),
            urllib.request.HTTPBasicAuthHandler(mgr),
        )

    def login(self) -> bool:
        body = urllib.parse.urlencode(
            {"username": self.username, "password": self.password}
        ).encode()
        req = urllib.request.Request(self.base + "/session/check_login", data=body)
        try:
            with self.opener.open(req, timeout=5) as resp:
                resp.read()
            return True
        except (urllib.error.URLError, TimeoutError, OSError):
            token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            req = urllib.request.Request(
                self.base + "/system/status.json",
                headers={"Authorization": f"Basic {token}"},
            )
            try:
                with self.opener.open(req, timeout=5) as resp:
                    resp.read()
                return True
            except (urllib.error.URLError, TimeoutError, OSError):
                return False

    def get_json(self, path: str) -> Any:
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
        req = urllib.request.Request(
            self.base + path,
            headers={
                "Accept": "application/json",
                "Authorization": f"Basic {token}",
            },
        )
        with self.opener.open(req, timeout=8) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        if not raw.strip():
            return {}
        return json.loads(raw)


def wait_for_kismet(
    client: KismetClient,
    proc: subprocess.Popen[bytes] | None = None,
    timeout: int = 45,
) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc is not None and proc.poll() is not None:
            return False
        if client.login():
            try:
                client.get_json("/system/status.json")
                return True
            except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
                pass
        time.sleep(1)
    return False


def gps_from_status(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {"valid": False}
    candidates = [
        payload,
        kg(payload, "kismet.common.location", default={}) or {},
        kg(payload, "kismet.gps.location", default={}) or {},
        kg(payload, "kismet.gps.last_location", default={}) or {},
        kg(payload, "kismet.gps.best_location", default={}) or {},
    ]
    for blob in candidates:
        if not isinstance(blob, dict):
            continue
        pt = kg(blob, "kismet.common.location.geopoint", default=None)
        lat = kg(blob, "kismet.common.location.lat", default=None)
        lon = kg(blob, "kismet.common.location.lon", default=None)
        if isinstance(pt, (list, tuple)) and len(pt) >= 2:
            lon, lat = pt[0], pt[1]
        alt = kg(blob, "kismet.common.location.alt", default="")
        fix = kg(blob, "kismet.common.location.fix", default="")
        valid_flag = kg(blob, "kismet.common.location.valid", default=None)
        if valid_coord(lat, lon):
            return {
                "valid": True,
                "lat": float(lat),
                "lon": float(lon),
                "alt": alt,
                "fix": fix,
                "flag": valid_flag,
            }
    return {"valid": False}


def live_counts(client: KismetClient) -> dict[str, Any]:
    out: dict[str, Any] = {
        "devices": 0,
        "phys": {},
        "gps": {"valid": False},
        "packets": 0,
    }
    try:
        status = client.get_json("/system/status.json")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        return out
    out["devices"] = kg(status, "kismet.system.devices.count", default=0) or 0
    out["packets"] = kg(status, "kismet.system.packets.rrd", "kismet.common.rrd.last_value", default=0) or 0
    gps_info: dict[str, Any] = {"valid": False, "connected": False}
    try:
        all_gps = client.get_json("/gps/all_gps.json")
        if isinstance(all_gps, list) and all_gps:
            gps_info = gps_from_status(all_gps[0])
            gps_info["connected"] = bool(kg(all_gps[0], "kismet.gps.connected", default=0))
            gps_info["name"] = kg(all_gps[0], "kismet.gps.name", default="")
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, TypeError):
        pass
    try:
        locp = gps_from_status(client.get_json("/gps/location.json"))
        if locp.get("valid"):
            gps_info.update(locp)
            gps_info["connected"] = True
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        locp = gps_from_status(status)
        if locp.get("valid"):
            gps_info.update(locp)
            gps_info["connected"] = True
    if not gps_info.get("valid"):
        gd = gpsd_live_fix()
        if gd.get("valid"):
            gps_info.update(gd)
        else:
            if gd.get("connected"):
                gps_info["connected"] = True
            if gd.get("sats"):
                gps_info["sats"] = gd["sats"]
            if gd.get("mode"):
                gps_info["mode"] = gd["mode"]
    out["gps"] = gps_info
    try:
        phys = client.get_json("/phy/all_phys.json")
        if isinstance(phys, list):
            for phy in phys:
                name = kg(phy, "kismet.phy.name", default="") or kg(phy, "kismet.phy.phyname", default="")
                count = kg(phy, "kismet.phy.devices", default=None)
                if count is None:
                    count = kg(phy, "kismet.phy.phy_devices", default=0)
                if name:
                    out["phys"][name] = count
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError):
        pass
    return out


def write_httpd_conf(homedir: Path, username: str, password: str) -> None:
    # Kismet treats --homedir as $HOME and reads $HOME/.kismet/kismet_httpd.conf
    confdir = homedir / ".kismet"
    confdir.mkdir(parents=True, exist_ok=True)
    (confdir / "kismet_httpd.conf").write_text(
        f"httpd_username={username}\nhttpd_password={password}\n",
        encoding="utf-8",
    )


def write_override_conf(
    path: Path,
    *,
    gps_line: str,
    http_port: int,
    pcap: bool,
    hide_data: bool,
    test_name: str,
    operator: str,
    hop_rate: int,
) -> None:
    lines = [
        f"server_name={TOOL_ID}",
        f"server_description={sanitize_title(test_name)} / {sanitize_title(operator)}",
        f"server_location={test_name}",
        "httpd_bind_address=127.0.0.1",
        f"httpd_port={http_port}",
        "log_types=" + ("kismet,pcapng" if pcap else "kismet"),
        "kis_log_devices=true",
        "kis_log_messages=true",
        "kis_log_alerts=true",
        "kis_log_gps_track=true",
        "kis_log_system_status=true",
        "kis_log_packets=" + ("true" if pcap else "false"),
        "kis_log_data_packets=" + ("true" if pcap else "false"),
        "channel_hop=true",
        f"channel_hop_speed={hop_rate}/sec",
        "hidedata=" + ("true" if hide_data else "false"),
        "remote_capture_listen=127.0.0.1",
    ]
    if gps_line:
        lines.append(gps_line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def start_kismet(
    kismet_bin: str,
    *,
    homedir: Path,
    override: Path,
    outdir: Path,
    title: str,
    sources: list[str],
    log_path: Path,
) -> subprocess.Popen[bytes]:
    cmd = [
        kismet_bin,
        "--no-ncurses",
        "--no-console-wrapper",
        "--homedir",
        str(homedir),
        "--override",
        str(override),
        "-p",
        str(outdir),
        "-t",
        title,
        "-T",
        "kismet",
    ]
    for source in sources:
        cmd.extend(["-c", source])
    log("Starting Kismet: " + " ".join(cmd))
    handle = log_path.open("wb")
    proc = subprocess.Popen(
        cmd,
        stdout=handle,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    proc._log_handle = handle  # type: ignore[attr-defined]
    return proc


def stop_kismet(proc: subprocess.Popen[bytes] | None) -> None:
    if proc is None:
        return
    handle = getattr(proc, "_log_handle", None)
    if proc.poll() is None:
        try:
            os.killpg(proc.pid, signal.SIGINT)
        except OSError:
            proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=12)
        except subprocess.TimeoutExpired:
            log("Kismet did not exit on SIGINT; sending SIGTERM.", "warn")
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError:
                proc.terminate()
            try:
                proc.wait(timeout=6)
            except subprocess.TimeoutExpired:
                log("Kismet still running; sending SIGKILL.", "warn")
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except OSError:
                    proc.kill()
                proc.wait(timeout=3)
    if handle:
        try:
            handle.close()
        except OSError:
            pass


def find_kismet_db(outdir: Path) -> Path | None:
    files = sorted(outdir.glob("*.kismet"), key=lambda p: p.stat().st_mtime, reverse=True)
    return files[0] if files else None


def load_device_json(raw: Any) -> dict[str, Any]:
    if not raw:
        return {}
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", errors="replace")
    if isinstance(raw, dict):
        return raw
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if isinstance(parsed, str):
        try:
            parsed = json.loads(parsed)
        except json.JSONDecodeError:
            return {}
    return parsed if isinstance(parsed, dict) else {}


def unique_join(values: list[str]) -> str:
    seen: list[str] = []
    for value in values:
        text = str(value).strip()
        if text and text not in seen:
            seen.append(text)
    return "; ".join(seen)


def extract_ssids(dot11: dict[str, Any]) -> tuple[str, str]:
    beaconed: list[str] = []
    probed: list[str] = []
    last_b = kg(dot11, "dot11.device.last_beaconed_ssid_record", default={}) or {}
    ssid = kg(last_b, "dot11.advertisedssid.ssid", default="")
    if ssid:
        beaconed.append(str(ssid))
    adv = kg(dot11, "dot11.device.advertised_ssid_map", default={}) or {}
    if isinstance(adv, dict):
        for rec in adv.values():
            if isinstance(rec, dict):
                value = kg(rec, "dot11.advertisedssid.ssid", default="")
                if value:
                    beaconed.append(str(value))
    last_p = kg(dot11, "dot11.device.last_probed_ssid_record", default={}) or {}
    pssid = kg(last_p, "dot11.probedssid.ssid", default="")
    if pssid:
        probed.append(str(pssid))
    pmap = kg(dot11, "dot11.device.probed_ssid_map", default={}) or {}
    if isinstance(pmap, dict):
        for rec in pmap.values():
            if isinstance(rec, dict):
                value = kg(rec, "dot11.probedssid.ssid", default="") or rec.get("ssid", "")
                if value:
                    probed.append(str(value))
            elif isinstance(rec, str):
                probed.append(rec)
    return unique_join(beaconed), unique_join(probed)


def extract_machine_names(devjson: dict[str, Any], ssid: str, bt_name: str) -> str:
    names: list[str] = []
    for value in (
        kg(devjson, "kismet.device.base.name", default=""),
        kg(devjson, "kismet.device.base.commonname", default=""),
        ssid,
        bt_name,
        kg(devjson, "dot11.device", "dot11.device.dhcp_host", default=""),
        kg(devjson, "dot11.device", "dot11.device.wps_device_name", default=""),
        kg(devjson, "dot11.device", "dot11.device.wps_manuf", default=""),
        kg(devjson, "dot11.device", "dot11.device.last_bssid", default=""),
    ):
        text = str(value).strip()
        mac = str(kg(devjson, "kismet.device.base.macaddr", default="")).upper()
        if not text or text.upper() == mac:
            continue
        names.append(text)
    return unique_join(names)


def extract_location(devjson: dict[str, Any], row: dict[str, Any]) -> dict[str, str]:
    loc = {
        "gps_lat": "",
        "gps_lon": "",
        "gps_alt": "",
        "gps_avg_lat": "",
        "gps_avg_lon": "",
        "gps_min": "",
        "gps_max": "",
        "gps_last": "",
    }
    avg_lat, avg_lon = row.get("avg_lat"), row.get("avg_lon")
    if valid_coord(avg_lat, avg_lon):
        loc["gps_avg_lat"] = f"{float(avg_lat):.6f}"
        loc["gps_avg_lon"] = f"{float(avg_lon):.6f}"
        loc["gps_lat"] = loc["gps_avg_lat"]
        loc["gps_lon"] = loc["gps_avg_lon"]
    min_pair = fmt_coord(row.get("min_lat"), row.get("min_lon"))
    max_pair = fmt_coord(row.get("max_lat"), row.get("max_lon"))
    loc["gps_min"] = min_pair
    loc["gps_max"] = max_pair

    blob = kg(devjson, "kismet.device.base.location", default={}) or {}
    last = kg(blob, "kismet.common.location.last", default={}) or {}
    pt = kg(last, "kismet.common.location.geopoint", default=None)
    if isinstance(pt, (list, tuple)) and len(pt) >= 2 and valid_coord(pt[1], pt[0]):
        loc["gps_last"] = f"{float(pt[1]):.6f},{float(pt[0]):.6f}"
        loc["gps_lat"] = f"{float(pt[1]):.6f}"
        loc["gps_lon"] = f"{float(pt[0]):.6f}"
        alt = kg(last, "kismet.common.location.alt", default="")
        if alt not in ("", None, 0, 0.0):
            loc["gps_alt"] = str(alt)
    avg = kg(blob, "kismet.common.location.avg_loc", default={}) or {}
    apt = kg(avg, "kismet.common.location.geopoint", default=None)
    if isinstance(apt, (list, tuple)) and len(apt) >= 2 and valid_coord(apt[1], apt[0]):
        loc["gps_avg_lat"] = f"{float(apt[1]):.6f}"
        loc["gps_avg_lon"] = f"{float(apt[0]):.6f}"
        if not loc["gps_lat"]:
            loc["gps_lat"] = loc["gps_avg_lat"]
            loc["gps_lon"] = loc["gps_avg_lon"]
    return loc


def extract_device_record(row: dict[str, Any], collector_macs: set[str]) -> dict[str, Any]:
    devjson = row.get("devjson") or {}
    phy = row.get("phyname") or kg(devjson, "kismet.device.base.phyname", default="")
    mac = (row.get("devmac") or kg(devjson, "kismet.device.base.macaddr", default="")).upper()
    dtype = row.get("type") or kg(devjson, "kismet.device.base.type", default="")
    signal = kg(devjson, "kismet.device.base.signal", default={}) or {}
    freq = kg(devjson, "kismet.device.base.frequency", default="") or ""
    freq_mhz = ""
    try:
        freq_n = float(freq)
        freq_mhz = f"{freq_n / 1000.0:.3f}" if freq_n > 10000 else f"{freq_n:.3f}"
    except (TypeError, ValueError):
        freq_mhz = str(freq)
    dot11 = kg(devjson, "dot11.device", default={}) or {}
    bt = kg(devjson, "bluetooth.device", default={}) or {}
    ssid, probed = extract_ssids(dot11 if isinstance(dot11, dict) else {})
    bt_name = (
        kg(bt, "bluetooth.device.device_name", default="")
        or kg(bt, "bluetooth.device.name", default="")
        or kg(devjson, "kismet.device.base.name", default="")
    )
    if str(bt_name).upper() == mac:
        bt_name = ""
    loc = extract_location(devjson, row)
    last_sig = kg(signal, "kismet.common.signal.last_signal", default="")
    min_sig = kg(signal, "kismet.common.signal.min_signal", default="")
    max_sig = kg(signal, "kismet.common.signal.max_signal", default="")
    if last_sig in ("", None) and row.get("strongest_signal") not in (None, ""):
        last_sig = row.get("strongest_signal")
        max_sig = max_sig or last_sig
    rec = {
        "mac": mac,
        "phy": phy,
        "type": dtype,
        "ssid": ssid,
        "probed_ssids": probed,
        "machine_name": extract_machine_names(
            devjson, ssid, str(bt_name) if bt_name else ""
        ),
        "bt_name": bt_name or "",
        "manufacturer": kg(devjson, "kismet.device.base.manuf", default=""),
        "ieee_manufacturer": "Unknown",
        "channel": kg(devjson, "kismet.device.base.channel", default=""),
        "frequency_khz": freq,
        "frequency_mhz": freq_mhz,
        "signal_last_dbm": last_sig,
        "signal_min_dbm": min_sig,
        "signal_max_dbm": max_sig if max_sig not in ("", None) else row.get("strongest_signal", ""),
        "encryption": kg(devjson, "kismet.device.base.crypt", default=""),
        "first_seen": iso_utc(row.get("first_time")),
        "last_seen": iso_utc(row.get("last_time")),
        "packets": kg(devjson, "kismet.device.base.packets.total", default="")
        or kg(devjson, "kismet.device.base.packets.rx_total", default=""),
        "bytes_data": row.get("bytes_data", ""),
        "collector_radio": "yes" if mac in collector_macs else "no",
        **loc,
    }
    return rec


def extract_devices(db_path: Path, collector_macs: set[str]) -> list[dict[str, Any]]:
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    devices: list[dict[str, Any]] = []
    if "devices" not in tables:
        conn.close()
        return devices
    cur.execute(
        "SELECT first_time, last_time, phyname, devmac, strongest_signal, "
        "min_lat, min_lon, max_lat, max_lon, avg_lat, avg_lon, bytes_data, "
        "type, device FROM devices"
    )
    for row in cur.fetchall():
        mapped = {k: row[k] for k in row.keys()}
        mapped["devjson"] = load_device_json(mapped.pop("device"))
        devices.append(extract_device_record(mapped, collector_macs))
    conn.close()
    devices.sort(key=lambda d: (str(d.get("phy")), str(d.get("type")), str(d.get("mac"))))
    return devices


def extract_gps_track(db_path: Path) -> list[dict[str, Any]]:
    import sqlite3

    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = {r[0] for r in cur.fetchall()}
    points: list[dict[str, Any]] = []
    seen: set[tuple[Any, Any, Any]] = set()

    def add_point(ts: Any, lat: Any, lon: Any, alt: Any = "", source: str = "") -> None:
        if not valid_coord(lat, lon):
            return
        key = (ts, round(float(lat), 6), round(float(lon), 6))
        if key in seen:
            return
        seen.add(key)
        points.append(
            {
                "time": iso_utc(ts) if ts else "",
                "lat": f"{float(lat):.6f}",
                "lon": f"{float(lon):.6f}",
                "alt": alt if alt not in (None, "") else "",
                "source": source,
            }
        )

    if "snapshots" in tables:
        cur.execute("SELECT ts_sec, lat, lon, snaptype, json FROM snapshots")
        for row in cur.fetchall():
            add_point(row["ts_sec"], row["lat"], row["lon"], "", row["snaptype"] or "snapshot")
            raw = row["json"]
            if not raw:
                continue
            blob = load_device_json(raw)
            gps = gps_from_status(blob)
            if gps.get("valid"):
                add_point(row["ts_sec"], gps["lat"], gps["lon"], gps.get("alt"), "snapshot-json")
    if "data" in tables:
        cur.execute("SELECT ts_sec, lat, lon, alt FROM data")
        for row in cur.fetchall():
            add_point(row["ts_sec"], row["lat"], row["lon"], row["alt"], "data")
    if "packets" in tables:
        cur.execute(
            "SELECT ts_sec, lat, lon, alt FROM packets WHERE lat != 0 AND lon != 0 LIMIT 5000"
        )
        for row in cur.fetchall():
            add_point(row["ts_sec"], row["lat"], row["lon"], row["alt"], "packet")
    conn.close()
    points.sort(key=lambda p: p.get("time") or "")
    return points


def csv_fields() -> list[str]:
    return [
        "mac",
        "phy",
        "type",
        "ssid",
        "probed_ssids",
        "machine_name",
        "bt_name",
        "manufacturer",
        "ieee_manufacturer",
        "channel",
        "frequency_mhz",
        "frequency_khz",
        "signal_last_dbm",
        "signal_min_dbm",
        "signal_max_dbm",
        "encryption",
        "first_seen",
        "last_seen",
        "packets",
        "gps_lat",
        "gps_lon",
        "gps_alt",
        "gps_last",
        "gps_avg_lat",
        "gps_avg_lon",
        "gps_min",
        "gps_max",
        "collector_radio",
    ]


def write_csv(path: Path, rows: list[dict[str, Any]], fields: list[str]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def summarize_devices(devices: list[dict[str, Any]]) -> dict[str, int]:
    summary = {
        "total": len(devices),
        "wifi": 0,
        "wifi_ap": 0,
        "wifi_client": 0,
        "bluetooth": 0,
        "named": 0,
        "with_gps": 0,
        "with_ssid": 0,
        "ieee_known": 0,
        "ieee_unknown": 0,
    }
    for rec in devices:
        phy = str(rec.get("phy") or "").lower()
        dtype = str(rec.get("type") or "").lower()
        is_bt = "blue" in phy or dtype in {"btle", "br/edr", "classic"}
        if is_bt:
            summary["bluetooth"] += 1
        else:
            summary["wifi"] += 1
            if "ap" in dtype or rec.get("ssid"):
                summary["wifi_ap"] += 1
            if "client" in dtype or rec.get("probed_ssids"):
                summary["wifi_client"] += 1
        if rec.get("machine_name") or rec.get("bt_name"):
            summary["named"] += 1
        if rec.get("gps_lat") and rec.get("gps_lon"):
            summary["with_gps"] += 1
        if rec.get("ssid"):
            summary["with_ssid"] += 1
        if rec.get("ieee_manufacturer") and rec.get("ieee_manufacturer") != "Unknown":
            summary["ieee_known"] += 1
        else:
            summary["ieee_unknown"] += 1
    return summary


def write_reports(outdir: Path, payload: dict[str, Any]) -> None:
    json_path = outdir / f"{TOOL_ID}_report.json"
    txt_path = outdir / f"{TOOL_ID}_report.txt"
    md_path = outdir / f"{TOOL_ID}_report.md"
    csv_all = outdir / f"{TOOL_ID}_devices.csv"
    csv_wifi = outdir / f"{TOOL_ID}_wifi.csv"
    csv_bt = outdir / f"{TOOL_ID}_bluetooth.csv"
    csv_gps = outdir / f"{TOOL_ID}_gps_track.csv"

    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    devices: list[dict[str, Any]] = payload.get("devices") or []
    track: list[dict[str, Any]] = payload.get("gps_track") or []
    fields = csv_fields()
    write_csv(csv_all, devices, fields)
    wifi = [
        d
        for d in devices
        if "blue" not in str(d.get("phy") or "").lower()
        and str(d.get("type") or "").lower() not in {"btle", "br/edr"}
    ]
    bluetooth = [
        d
        for d in devices
        if "blue" in str(d.get("phy") or "").lower()
        or str(d.get("type") or "").lower() in {"btle", "br/edr"}
    ]
    write_csv(csv_wifi, wifi, fields)
    write_csv(csv_bt, bluetooth, fields)
    if track:
        write_csv(csv_gps, track, ["time", "lat", "lon", "alt", "source"])

    session = payload.get("session") or {}
    summary = payload.get("summary") or {}
    lines: list[str] = [
        TOOL_NAME,
        f"Generated (UTC): {payload.get('generated')}",
        f"Test: {session.get('test_name')}",
        f"Operator: {session.get('userid')} / {session.get('operator_name')}",
        f"ROE acknowledged: {session.get('roe_acknowledged')}",
        f"Kismet: {payload.get('kismet_version')}",
        f"Wi-Fi source: {session.get('wifi_source')}",
        f"Bluetooth source: {session.get('bluetooth_source') or '(none)'}",
        f"GPS: {session.get('gps') or '(none)'}",
        f"Channel hop: {session.get('hop_rate_per_sec', 5)}/sec "
        f"({session.get('hop_dwell_ms', hop_dwell_ms(DEFAULT_HOP_RATE))} ms/channel)",
        "Injection / deauth / association: no",
        "",
        "=== Executive summary ===",
        f"Devices observed: {summary.get('total', 0)}",
        f"  Wi-Fi: {summary.get('wifi', 0)}  (AP-like {summary.get('wifi_ap', 0)}, "
        f"client/probe {summary.get('wifi_client', 0)})",
        f"  Bluetooth: {summary.get('bluetooth', 0)}",
        f"  With SSID: {summary.get('with_ssid', 0)}",
        f"  With advertised name: {summary.get('named', 0)}",
        f"  With GPS: {summary.get('with_gps', 0)}",
        f"  IEEE vendor known: {summary.get('ieee_known', 0)}  "
        f"unknown: {summary.get('ieee_unknown', 0)}",
        f"GPS track points: {len(track)}",
        "",
        "=== Devices ===",
    ]
    if not devices:
        lines.append("None recorded. Confirm monitor mode, rfkill, and that Kismet stayed up.")
    for rec in devices:
        name = rec.get("machine_name") or rec.get("ssid") or rec.get("bt_name") or "-"
        gps = fmt_coord(rec.get("gps_lat"), rec.get("gps_lon")) or "no-fix"
        lines.append(
            f"{rec.get('mac')}  {rec.get('phy')} / {rec.get('type')}  "
            f"ssid={rec.get('ssid') or '-'}  name={name}  "
            f"ieee={rec.get('ieee_manufacturer') or 'Unknown'}  "
            f"sig={rec.get('signal_last_dbm')} dBm  freq={rec.get('frequency_mhz')} MHz  "
            f"gps={gps}"
        )
        if rec.get("probed_ssids"):
            lines.append(f"    probed: {rec['probed_ssids']}")
    lines.extend(
        [
            "",
            "=== Methodology ===",
            "Kismet was started with the selected Linux Wi-Fi interface in monitor "
            "mode (receive-only channel hop) and, if selected, the Linux Bluetooth "
            "HCI datasource. A USB NMEA GPS was attached when available so each "
            "device could be tagged with the surveyor's coordinates. After capture "
            "stopped, each MAC was matched against the IEEE OUI / MA-M / MA-S "
            "vendor registry (ieee_manufacturer; Unknown if unassigned). No packet "
            "injection, deauthentication, association, or credential attacks "
            "were enabled.",
            "Compare observed MACs / SSIDs / names against the authorized device "
            "inventory and the physical boundary approved for this test.",
        ]
    )
    txt_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    md = [
        f"# {TOOL_NAME}",
        "",
        f"- Generated (UTC): `{payload.get('generated')}`",
        f"- Test: **{session.get('test_name')}**",
        f"- Operator: `{session.get('userid')}` / {session.get('operator_name')}",
        f"- ROE acknowledged: {session.get('roe_acknowledged')}",
        f"- Kismet: {payload.get('kismet_version')}",
        f"- Wi-Fi: `{session.get('wifi_source')}`",
        f"- Bluetooth: `{session.get('bluetooth_source') or 'not used'}`",
        f"- GPS: `{session.get('gps') or 'not used'}`",
        f"- Channel hop: `{session.get('hop_rate_per_sec', 5)}/sec` "
        f"({session.get('hop_dwell_ms', hop_dwell_ms(DEFAULT_HOP_RATE))} ms/channel)",
        "- Injection / deauth / association: **no**",
        "",
        "## Summary",
        "",
        "| Metric | Count |",
        "| --- | ---: |",
        f"| Devices | {summary.get('total', 0)} |",
        f"| Wi-Fi | {summary.get('wifi', 0)} |",
        f"| Bluetooth | {summary.get('bluetooth', 0)} |",
        f"| With SSID | {summary.get('with_ssid', 0)} |",
        f"| With name | {summary.get('named', 0)} |",
        f"| With GPS | {summary.get('with_gps', 0)} |",
        f"| IEEE vendor known | {summary.get('ieee_known', 0)} |",
        f"| IEEE vendor unknown | {summary.get('ieee_unknown', 0)} |",
        f"| GPS track points | {len(track)} |",
        "",
        "## Devices",
        "",
    ]
    if not devices:
        md.append("None recorded.")
    else:
        md.extend(
            [
                "| MAC | PHY | Type | SSID / name | IEEE vendor | Signal | Freq MHz | GPS |",
                "| --- | --- | --- | --- | --- | ---: | ---: | --- |",
            ]
        )
        for rec in devices:
            name = rec.get("machine_name") or rec.get("ssid") or rec.get("bt_name") or ""
            gps = fmt_coord(rec.get("gps_lat"), rec.get("gps_lon")) or ""
            md.append(
                f"| `{rec.get('mac')}` | {rec.get('phy')} | {rec.get('type')} | "
                f"{name} | {rec.get('ieee_manufacturer') or 'Unknown'} | "
                f"{rec.get('signal_last_dbm')} | {rec.get('frequency_mhz')} | {gps} |"
            )
    md.extend(
        [
            "",
            "## Use of this report",
            "",
            "Match MAC / SSID / advertised names against the authorized inventory. "
            "Use GPS columns and `flute_gps_track.csv` to test whether "
            "authorized radios were observed only inside the approved physical "
            "boundary. Unexpected SSIDs, unnamed probing clients, or authorized "
            "MACs with coordinates outside that boundary are the findings this "
            "collection is meant to support.",
            "",
        ]
    )
    md_path.write_text("\n".join(md) + "\n", encoding="utf-8")

    log(f"JSON report : {json_path}", "ok")
    log(f"Text report : {txt_path}", "ok")
    log(f"Markdown    : {md_path}", "ok")
    log(f"All devices : {csv_all}", "ok")
    log(f"Wi-Fi CSV   : {csv_wifi}", "ok")
    log(f"Bluetooth   : {csv_bt}", "ok")
    if track:
        log(f"GPS track   : {csv_gps}", "ok")


def print_hardware(wifi: list[dict[str, Any]], bt: list[dict[str, Any]], gps: list[dict[str, Any]]) -> None:
    log("Wireless controllers", "hdr")
    if not wifi:
        log("None found.", "warn")
    for idx, item in enumerate(wifi, start=1):
        rec = "  [recommended]" if item.get("recommended") else ""
        print(f"  {idx}) {item['label']}{rec}")
        for line in item.get("detail") or []:
            print(f"      {line}")
    log("Bluetooth controllers", "hdr")
    if not bt:
        log("None found.", "warn")
    for idx, item in enumerate(bt, start=1):
        print(f"  {idx}) {item['label']}")
        for line in item.get("detail") or []:
            print(f"      {line}")
    log("GPS receivers", "hdr")
    if not gps:
        log("No USB serial GPS nodes under /dev/ttyUSB* or /dev/ttyACM*.", "warn")
    for idx, item in enumerate(gps, start=1):
        rec = "  [recommended]" if item.get("recommended") else ""
        print(f"  {idx}) {item['label']}{rec}")
        for line in item.get("detail") or []:
            print(f"      {line}")


def match_named(items: list[dict[str, Any]], name: str, key: str) -> dict[str, Any] | None:
    name_l = name.strip().lower()
    for item in items:
        if str(item.get(key, "")).lower() == name_l:
            return item
        if str(item.get("mac", "")).lower() == name_l:
            return item
    return None


def capture_loop(
    client: KismetClient,
    proc: subprocess.Popen[bytes],
    duration: int | None,
) -> None:
    started = time.time()
    log("Capture running. Press Ctrl-C to stop." + (f" Duration={duration}s." if duration else ""))
    log("Kismet web UI: http://127.0.0.1:2501 (local only)")
    try:
        while True:
            if proc.poll() is not None:
                log(f"Kismet exited early with code {proc.returncode}.", "err")
                return
            elapsed = int(time.time() - started)
            if duration is not None and elapsed >= duration:
                log("Duration reached; stopping capture.", "ok")
                return
            info = live_counts(client)
            gps = info.get("gps") or {}
            if gps.get("valid"):
                gps_s = f"{gps['lat']:.6f},{gps['lon']:.6f} fix={gps.get('fix') or '3D'}"
            elif gps.get("sats"):
                gps_s = f"searching ({gps['sats']} sats; window/sky)"
            elif gps.get("connected"):
                gps_s = "receiver up, 0 sats (place puck by a window; wait 1–5 min)"
            else:
                gps_s = "not connected"
            phys = info.get("phys") or {}
            phy_s = ", ".join(f"{k}={v}" for k, v in phys.items()) or f"total={info.get('devices')}"
            remain = ""
            if duration is not None:
                remain = f"  remaining={max(duration - elapsed, 0)}s"
            log(f"t={elapsed}s  GPS {gps_s}  devices {phy_s}{remain}")
            time.sleep(5)
    except KeyboardInterrupt:
        print()
        log("Stop requested.", "warn")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "The Magic Flute: passive Kismet Wi-Fi + Bluetooth survey with GPS tagging. "
            "Authorized use only. No injection."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "--setup",
        action="store_true",
        help="Install Kismet/helpers, add user to kismet+dialout, set capabilities (needs sudo)",
    )
    p.add_argument(
        "--check",
        action="store_true",
        help="Check hardware, packages, groups, and permissions; do not capture",
    )
    ieee = p.add_mutually_exclusive_group()
    ieee.add_argument(
        "--download-ieee",
        action="store_true",
        help="Download/refresh the IEEE MAC vendor database without asking (needs internet)",
    )
    ieee.add_argument(
        "--no-download-ieee",
        action="store_true",
        help="Never download the IEEE MAC vendor database (offline / air-gapped)",
    )
    p.add_argument("--i-have-roe", action="store_true", help="Confirm signed ROE / authorization")
    p.add_argument(
        "--userid",
        default="",
        help="Operator user ID (e.g. your username or employee ID)",
    )
    p.add_argument("--operator-name", default="", help="Operator full name")
    p.add_argument(
        "--test-name",
        default="",
        help="Test / location name, e.g. 'Warehouse 4 north wing'",
    )
    p.add_argument("--wifi", default="", help="Wi-Fi interface to use (skip picker)")
    p.add_argument("--bluetooth", default="", help="Bluetooth HCI to use (skip picker)")
    p.add_argument("--no-bluetooth", action="store_true", help="Do not enable a Bluetooth source")
    p.add_argument("--gps-device", default="", help="GPS serial device (default: autodetect)")
    p.add_argument("--gps-baud", type=int, default=0, help="GPS baud (default: autodetect or 4800)")
    p.add_argument("--no-gps", action="store_true", help="Do not attach a GPS")
    p.add_argument("--duration", type=int, default=0, help="Stop after N seconds (0 = until Ctrl-C)")
    p.add_argument(
        "--hop-rate",
        default="",
        help=(
            f"Wi-Fi channel hops per second (default: {DEFAULT_HOP_RATE}; "
            f"{MIN_HOP_RATE}-{MAX_HOP_RATE}). {DEFAULT_HOP_RATE} hops/sec = "
            f"{hop_dwell_ms(DEFAULT_HOP_RATE)} ms per channel"
        ),
    )
    p.add_argument("-o", "--outdir", default="", help="Output directory")
    p.add_argument("--http-port", type=int, default=2501, help="Kismet web UI port (localhost only)")
    p.add_argument("--pcap", action="store_true", help="Also write pcapng / packet log (large)")
    p.add_argument("--hide-data", action="store_true", help="Truncate 802.11 data payloads in Kismet")
    p.add_argument("--list-only", action="store_true", help="List controllers and GPS, then exit")
    p.add_argument("--dry-run", action="store_true", help="Show the Kismet command and exit")
    return p


def main() -> int:
    args = build_parser().parse_args()
    print_banner()
    if args.no_download_ieee:
        ieee_policy = "no"
    elif args.download_ieee:
        ieee_policy = "yes"
    else:
        ieee_policy = "ask"

    if args.setup:
        return run_setup(ieee_policy)
    if args.check:
        return run_check(ieee_policy)
    if args.list_only:
        print_hardware(list_wifi_controllers(), list_bt_controllers(), list_gps_devices())
        return 0

    confirm_roe(args.i_have_roe)
    blockers = prepare_system()
    for msg in blockers:
        log(msg, "err")
    if blockers:
        return 1

    ensure_ieee_oui_database(ieee_policy)

    kismet_bin = which_or_exit("kismet")
    which_or_exit("kismet_cap_linux_wifi")
    version = kismet_version(kismet_bin)
    log(f"Kismet: {version}")
    if not is_root():
        log(
            "Not running as root. GPS and leftover monitor-interface cleanup work "
            f"best with sudo. Prefer: sudo python3 {Path(__file__).name}",
            "warn",
        )

    wifi_list = list_wifi_controllers()
    bt_list = list_bt_controllers()
    gps_list = list_gps_devices()

    if not wifi_list:
        log(
            "No Wi-Fi controllers found. Plug in a USB adapter that supports "
            "monitor mode (for example Panda/MediaTek mt76) and retry.",
            "err",
        )
        return 1

    if args.wifi:
        wifi = match_named(wifi_list, args.wifi, "iface")
        if wifi is None:
            log(f"Wi-Fi interface not found: {args.wifi}", "err")
            return 1
    else:
        default_wifi = 0
        for idx, item in enumerate(wifi_list):
            if item.get("recommended"):
                default_wifi = idx
                break
        picked = ask_choice("Select the wireless controller", wifi_list, default_index=default_wifi)
        wifi = picked or wifi_list[0]

    bt: dict[str, Any] | None = None
    if args.no_bluetooth:
        log("Bluetooth source disabled.")
    elif args.bluetooth:
        bt = match_named(bt_list, args.bluetooth, "iface")
        if bt is None:
            log(f"Bluetooth controller not found: {args.bluetooth}", "err")
            return 1
    elif bt_list:
        bt = ask_choice(
            "Select the Bluetooth controller",
            bt_list,
            allow_skip=True,
            default_index=0,
        )
    else:
        log("No Bluetooth controller found; continuing Wi-Fi only.", "warn")

    gps: dict[str, Any] | None = None
    if args.no_gps:
        log("GPS disabled.")
    elif args.gps_device:
        gps = {
            "device": args.gps_device,
            "baud": args.gps_baud or 4800,
            "hint": "user-specified",
            "label": args.gps_device,
        }
    elif gps_list:
        gps = gps_list[0]
        if args.gps_baud:
            gps = dict(gps)
            gps["baud"] = args.gps_baud
        log(f"Using GPS {gps['label']} @ {gps.get('baud')} baud.", "ok")
    else:
        log(
            "No GPS found. Locations will not be tagged. Attach a USB NMEA GPS "
            "(for example a GlobalSat BU-353S4 on /dev/ttyUSB0) if coordinates are required.",
            "warn",
        )

    userid = args.userid or ask_text("Operator UserID (e.g. your username or employeeID)")
    operator_name = args.operator_name or ask_text("Operator name")
    test_name = args.test_name or ask_text("Test name (e.g. Warehouse 4 north wing)")
    if args.hop_rate:
        try:
            hop_rate = parse_hop_rate(args.hop_rate)
        except ValueError as exc:
            log(str(exc), "err")
            return 2
    else:
        hop_rate = ask_hop_rate() if sys.stdin.isatty() else DEFAULT_HOP_RATE
    log(
        f"Channel hop: {hop_rate}/sec ({hop_dwell_ms(hop_rate)} ms dwell per channel).",
        "ok",
    )

    if not wifi.get("monitor"):
        log(
            f"{wifi['iface']} did not advertise monitor mode. Kismet may still try; "
            "if capture is empty, use a USB adapter that supports monitor mode.",
            "warn",
        )
    if str(wifi.get("rfkill") or "") in {"soft-blocked", "hard-blocked"}:
        log(f"{wifi['iface']} is {wifi['rfkill']}. Will attempt rfkill unblock.", "warn")

    title = sanitize_title(test_name)
    outdir = Path(args.outdir).expanduser().resolve() if args.outdir else Path(f"{TOOL_ID}_{timestamp()}").resolve()
    http_port = args.http_port
    sources = [
        f"{wifi['iface']}:name={sanitize_title(wifi.get('hint') or wifi['iface'])},"
        f"hop=true,hoprate={hop_rate}/sec"
    ]
    if bt:
        sources.append(
            f"{bt['iface']}:type=linuxbluetooth,name={sanitize_title(bt.get('label') or bt['iface'])}"
        )
    gps_line = ""
    gpsd_proc: subprocess.Popen[bytes] | None = None
    if gps:
        gps_path = Path(gps["device"])
        if not is_root() and not os.access(gps_path, os.R_OK):
            log(
                f"{gps['device']} is not readable. Join the dialout group "
                f"(sudo python3 {Path(__file__).name} --setup, then log out/in) "
                "or re-run this capture with sudo. Continuing without GPS.",
                "warn",
            )
            gps = None
        else:
            gps_line, gpsd_proc = configure_gps_backend(
                gps, start_daemon=not args.dry_run
            )

    print()
    log("Capture plan", "hdr")
    log(f"Operator   : {userid} / {operator_name}")
    log(f"Test       : {test_name}")
    log(f"Wi-Fi      : {wifi['iface']} ({wifi.get('hint')})  mac={wifi.get('mac')}")
    log(f"Bluetooth  : {bt['iface'] if bt else '(disabled)'}")
    log(f"GPS        : {gps['device'] + ' @ ' + str(gps.get('baud')) + ' baud' if gps else '(disabled)'}")
    log(f"Hop rate   : {hop_rate}/sec ({hop_dwell_ms(hop_rate)} ms/channel)")
    log(f"Duration   : {args.duration or 'until Ctrl-C'}")
    log(f"Output     : {outdir}")
    log("Passive    : no injection, deauth, association, or pairing")

    if args.dry_run:
        log("Dry run — not starting Kismet.", "warn")
        print("Sources: " + " | ".join(sources))
        if gps_line:
            print(gps_line)
        return 0

    if sys.stdin.isatty() and not args.i_have_roe:
        go = ask_text("Start passive capture? [Y/n]", default="Y", required=False)
        if go.lower() in {"n", "no"}:
            log("Aborted.", "warn")
            return 2

    if port_open("127.0.0.1", http_port):
        log(
            f"Port {http_port} is already in use. Stop the other Kismet instance "
            "or pass --http-port.",
            "err",
        )
        return 1

    outdir.mkdir(parents=True, exist_ok=True)
    homedir = outdir / "kismet_home"
    password = secrets.token_urlsafe(16)
    write_httpd_conf(homedir, KISMET_HTTP_USER, password)
    override = outdir / "kismet_override.conf"
    write_override_conf(
        override,
        gps_line=gps_line,
        http_port=http_port,
        pcap=args.pcap,
        hide_data=args.hide_data,
        test_name=test_name,
        operator=operator_name,
        hop_rate=hop_rate,
    )

    session = {
        "tool": TOOL_ID,
        "tool_name": TOOL_NAME,
        "generated_start": datetime.now(timezone.utc).isoformat(),
        "userid": userid,
        "operator_name": operator_name,
        "test_name": test_name,
        "roe_acknowledged": True,
        "roe_method": "cli" if args.i_have_roe else "interactive YES",
        "sudo_user": os.environ.get("SUDO_USER") or os.environ.get("USER") or "",
        "host": socket.gethostname(),
        "wifi_iface": wifi["iface"],
        "wifi_mac": wifi.get("mac"),
        "wifi_source": sources[0],
        "bluetooth_iface": bt["iface"] if bt else "",
        "bluetooth_mac": bt.get("mac") if bt else "",
        "bluetooth_source": sources[1] if bt else "",
        "gps": gps_line or "",
        "gps_device": gps["device"] if gps else "",
        "gps_mode": (gps or {}).get("mode") or "",
        "http_port": http_port,
        "hop_rate_per_sec": hop_rate,
        "hop_dwell_ms": hop_dwell_ms(hop_rate),
        "passive": True,
        "injection": False,
        "kismet_version": version,
    }
    (outdir / "operator_session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")

    unblock_radios()
    nm_set_managed(wifi["iface"], False)

    client = KismetClient(f"http://127.0.0.1:{http_port}", KISMET_HTTP_USER, password)
    kismet_log = outdir / "kismet_server.log"
    proc: subprocess.Popen[bytes] | None = None
    db_path: Path | None = None
    try:
        proc = start_kismet(
            kismet_bin,
            homedir=homedir,
            override=override,
            outdir=outdir,
            title=title,
            sources=sources,
            log_path=kismet_log,
        )
        log("Waiting for Kismet HTTP API...")
        ready = wait_for_kismet(client, proc)
        if not ready:
            log("Kismet HTTP API login failed. Last log lines:", "warn")
            if kismet_log.exists():
                tail = kismet_log.read_text(encoding="utf-8", errors="replace").splitlines()[-40:]
                print("\n".join(tail))
            if proc.poll() is not None:
                log("Kismet process exited during startup.", "err")
            elif args.duration:
                log(
                    f"Sources may still be capturing; waiting {args.duration}s "
                    "then exporting the log.",
                    "warn",
                )
                time.sleep(args.duration)
        else:
            log(f"Kismet is up (pid {proc.pid}). Web UI http://127.0.0.1:{http_port}", "ok")
            capture_loop(client, proc, args.duration or None)
    finally:
        log("Stopping Kismet so the log can be finalized...")
        stop_kismet(proc)
        stop_gpsd(gpsd_proc)
        restore_wifi(wifi["iface"])

    time.sleep(1)
    db_path = find_kismet_db(outdir)
    if db_path is None:
        log("No .kismet database found. See kismet_server.log.", "err")
        chown_tree(outdir)
        return 1
    log(f"Kismet DB: {db_path}", "ok")

    collector = {str(wifi.get("mac") or "").upper()}
    if bt and bt.get("mac"):
        collector.add(str(bt["mac"]).upper())
    collector.discard("")

    devices = extract_devices(db_path, collector)
    apply_ieee_manufacturers(devices, load_ieee_oui_table())
    track = extract_gps_track(db_path)
    summary = summarize_devices(devices)
    session["generated_end"] = datetime.now(timezone.utc).isoformat()
    session["kismet_db"] = str(db_path)
    payload = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "kismet_version": version,
        "kismet_db": str(db_path),
        "session": session,
        "summary": summary,
        "devices": devices,
        "gps_track": track,
    }
    write_reports(outdir, payload)
    (outdir / "operator_session.json").write_text(json.dumps(session, indent=2), encoding="utf-8")
    chown_tree(outdir)

    print()
    log(
        f"Done. {summary.get('total', 0)} device(s), "
        f"{summary.get('with_gps', 0)} with GPS, "
        f"{len(track)} track point(s).",
        "ok",
    )
    log("Use the CSVs to match inventory and to check authorized physical boundaries.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print()
        log("Interrupted.", "warn")
        sys.exit(130)
