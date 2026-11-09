#!/usr/bin/env python3
"""Checks for the live survey display and the capture pieces it sits on.

No Kismet process and no radio. Run from the repo:

    python3 tests/test_live_dashboard.py
    python3 flute.py --self-test
"""

from __future__ import annotations

import fcntl
import io
import os
import pty
import struct
import subprocess
import sys
import tempfile
import termios
import unittest
import urllib.error
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import flute


def _view(**overrides: object) -> flute.DashboardView:
    devices = [
        {
            "mac": f"AA:BB:CC:DD:EE:{index:02d}",
            "signal": -20 - index,
            "phy": "IEEE802.11",
            "type": "Wi-Fi AP",
            "ssid": f"AP-{index:02d}",
            "channel": str(index + 1),
            "frequency": 2437000,
            "tx_power": 20,
        }
        for index in range(1, 12)
    ]
    base = dict(
        userid="jsmith",
        operator_name="Jane Doe",
        test_name="Warehouse 4 north wing",
        host="survey-host",
        gps_text="33.400000,-81.700000 fix=3D",
        started="2026-11-09T15:04:05+00:00",
        elapsed_s=75,
        duration_s=600,
        hop_rate=5,
        outdir="/tmp/flute_demo",
        kismet_version="2026.10.0",
        http_port=2501,
        devices_found=128,
        in_range=14,
        hops=2401,
        hop_rows=88,
        packets=12,
        phys_text="IEEE802.11=90, BR/EDR=38",
        wifi_iface="mt7921-0",
        wifi_source_type="usbwifi",
        wifi_hint="Panda USB / MediaTek via usbwifi (preferred survey adapter)",
        wifi_mac="00:11:22:33:44:55",
        wifi_driver="mt7921u",
        wifi_usb="0e8d:7961",
        bluetooth="hci0",
        gps_device="/dev/ttyUSB0  GlobalSat",
        devices=flute.rank_in_range(devices, 10),
        message="",
        poll_ok=True,
    )
    base.update(overrides)
    return flute.DashboardView(**base)


def _assert_frame(testcase: unittest.TestCase, view: flute.DashboardView, rows: int, cols: int) -> list[str]:
    lines = flute.frame_text(view, rows, cols)
    testcase.assertEqual(len(lines), rows)
    for line in lines:
        testcase.assertEqual(len(line), cols, line)
    return lines


class DashboardLayoutTests(unittest.TestCase):
    def test_every_size_is_exact(self) -> None:
        view = _view()
        sizes = [
            (1, 1),
            (2, 3),
            (5, 10),
            (8, 20),
            (9, 40),
            (10, 36),
            (12, 40),
            (16, 60),
            (24, 80),
            (25, 81),
            (30, 100),
            (40, 120),
            (50, 200),
            (24, 40),
        ]
        for rows, cols in sizes:
            _assert_frame(self, view, rows, cols)

    def test_standard_terminal_shows_the_survey(self) -> None:
        lines = _assert_frame(self, _view(), 24, 80)
        text = "\n".join(lines)
        self.assertTrue(lines[0].startswith("╭"))
        self.assertTrue(lines[-1].startswith("╰"))
        self.assertIn("THE MAGIC FLUTE", text)
        self.assertIn("jsmith", text)
        self.assertIn("Warehouse 4 north wing", text)
        self.assertIn("33.400000,-81.700000", text)
        self.assertIn("Jane Doe", text)
        self.assertIn("2401", text)
        self.assertIn("128", text)
        self.assertIn("mt7921-0", text)
        self.assertIn("Panda USB", text)
        self.assertIn("hci0", text)
        self.assertIn("IN RANGE", text)
        self.assertIn("TOP 10 OF 14", text)
        self.assertIn("AP-01", text)
        self.assertNotIn("AP-11", text)
        # Strongest of the ranked set is AP-01, before the weaker AP-10.
        self.assertLess(text.index("AP-01"), text.index("AP-10"))

    def test_wide_terminal_keeps_the_radio_mac(self) -> None:
        text = "\n".join(_assert_frame(self, _view(), 30, 160))
        self.assertIn("00:11:22:33:44:55", text)
        self.assertIn("0e8d:7961", text)
        self.assertIn("mt7921u", text)

    def test_short_terminal_keeps_identity_and_hops(self) -> None:
        text = "\n".join(_assert_frame(self, _view(), 12, 80))
        self.assertIn("jsmith", text)
        self.assertIn("Warehouse 4 north wing", text)
        self.assertIn("2401", text)
        self.assertIn("mt7921-0", text)
        self.assertIn("AP-01", text)
        # 12 rows: bottom half holds the header, four devices, and the border.
        self.assertNotIn("AP-05", text)

    def test_tiny_terminal_does_not_draw_a_broken_box(self) -> None:
        lines = _assert_frame(self, _view(), 5, 20)
        self.assertNotIn("╭", lines[0])
        text = "\n".join(lines)
        self.assertIn("MAGIC", text)
        self.assertIn("2401", text)

    def test_warning_lands_on_the_footer(self) -> None:
        text = "\n".join(
            _assert_frame(self, _view(message="hop poll timed out"), 24, 80)
        )
        self.assertIn("hop poll timed out", text)
        self.assertNotIn("tokyo night", text.splitlines()[-1])

    def test_empty_range_is_explicit(self) -> None:
        text = "\n".join(_assert_frame(self, _view(devices=[], in_range=0), 24, 80))
        self.assertIn("no devices in range", text)

    def test_columns_fill_the_width(self) -> None:
        for width in range(0, 140):
            columns = flute.layout_columns(width)
            if width == 0:
                self.assertEqual(columns, [])
                continue
            total = sum(col_w for _key, col_w, _header in columns) + len(columns) - 1
            self.assertEqual(total, width, columns)
            self.assertGreaterEqual(columns[-1][1], 1)


class RankingTests(unittest.TestCase):
    def test_strongest_signal_first_and_one_row_per_mac(self) -> None:
        devices = [
            {"mac": "bb:00:00:00:00:02", "signal": -40, "ssid": "b"},
            {"mac": "aa:00:00:00:00:01", "signal": -40, "ssid": "a"},
            {"mac": "cc:00:00:00:00:03", "signal": -20, "ssid": "c"},
            {"mac": "dd:00:00:00:00:04", "signal": 0, "ssid": "silent"},
            {"mac": "ee:00:00:00:00:05", "signal": -90, "ssid": "e"},
            {"mac": "aa:00:00:00:00:01", "signal": -15, "ssid": "a-closer"},
            {"mac": "", "signal": -10, "ssid": "no-mac"},
        ]
        ranked = flute.rank_in_range(devices, 10)
        self.assertEqual(
            [item["mac"] for item in ranked],
            [
                "AA:00:00:00:00:01",
                "CC:00:00:00:00:03",
                "BB:00:00:00:00:02",
                "EE:00:00:00:00:05",
                "DD:00:00:00:00:04",
            ],
        )
        self.assertEqual(ranked[0]["ssid"], "a-closer")
        self.assertNotIn("_rssi", ranked[0])

    def test_top_ten_drops_the_weakest(self) -> None:
        devices = [
            {"mac": f"02:00:00:00:00:{index:02x}", "signal": -30 - index, "ssid": f"n{index}"}
            for index in range(1, 13)
        ]
        ranked = flute.rank_in_range(devices, 10)
        self.assertEqual(len(ranked), 10)
        macs = {item["mac"] for item in ranked}
        self.assertNotIn("02:00:00:00:00:0C", macs)
        self.assertEqual(ranked[0]["ssid"], "n1")


class SurveyScreenTests(unittest.TestCase):
    def setUp(self) -> None:
        flute._live_field_index = 0
        flute._log_hook = None

    def tearDown(self) -> None:
        flute._live_field_index = 0
        flute._log_hook = None

    def test_screen_counts_found_hops_and_current_range(self) -> None:
        screen = flute.DashboardScreen(
            {
                "userid": "jsmith",
                "operator_name": "Jane Doe",
                "test_name": "Lab",
                "host": "survey-host",
                "wifi_iface": "mt7921-0",
                "wifi_source_type": "usbwifi",
                "wifi_hint": "Panda USB / MediaTek",
                "bluetooth": "hci0",
                "gps_device": "/dev/ttyUSB0",
                "hop_rate": 5,
                "http_port": 2501,
            },
            duration=30,
            hop_rate=5,
        )
        screen.note_heard(
            [
                {"mac": "aa:bb:cc:dd:ee:01", "signal": -70, "phy": "IEEE802.11", "ssid": "far"},
                {"mac": "aa:bb:cc:dd:ee:02", "signal": -35, "phy": "BTLE", "name": "phone"},
            ],
            True,
        )
        screen.note_counts(
            {
                "devices": 0,
                "packets": 4,
                "phys": {"IEEE802.11": 1},
                "gps": {"valid": True, "lat": 33.4, "lon": -81.7, "fix": "3D"},
            }
        )
        view = screen.make_view(elapsed_s=9, hops=40, hop_rows=6)
        self.assertEqual(view.devices_found, 2)
        self.assertEqual(view.in_range, 2)
        self.assertEqual(view.hops, 40)
        self.assertEqual(view.devices[0]["mac"], "AA:BB:CC:DD:EE:02")
        self.assertIn("fix=3D", view.gps_text)
        screen.note_counts({"devices": 9, "packets": 4, "phys": {}, "gps": {"valid": False}})
        screen.note_heard([], True)
        view = screen.make_view(9, 41, 6)
        self.assertEqual(view.devices_found, 9)
        self.assertEqual(view.in_range, 0)
        self.assertEqual(view.devices, [])
        screen.note_heard(None, False)
        self.assertFalse(screen.poll_ok)
        self.assertEqual(screen.heard, [])

    def test_failed_poll_keeps_the_previous_sample(self) -> None:
        screen = flute.DashboardScreen({})
        screen.note_heard([{"mac": "aa:bb:cc:dd:ee:10", "signal": -40}], True)
        screen.note_heard(None, False)
        self.assertEqual(len(screen.heard), 1)
        self.assertFalse(screen.poll_ok)
        view = screen.make_view(1, 2, 1)
        self.assertEqual(view.devices[0]["mac"], "AA:BB:CC:DD:EE:10")
        text = "\n".join(flute.frame_text(view, 24, 80))
        self.assertIn("HOLDING LAST SAMPLE", text)

    def test_name_field_rejection_keeps_ssid_fields(self) -> None:
        class Client:
            def __init__(self) -> None:
                self.payloads: list[list] = []

            def post_json(self, path: str, payload: dict, timeout: float = 2.5) -> list:
                fields = payload["fields"]
                self.payloads.append(fields)
                aliases = {item[1] for item in fields}
                if "name" in aliases:
                    raise urllib.error.URLError("Kismet POST failed: application/json: HTTP 500")
                return [
                    {
                        "mac": "aa:bb:cc:dd:ee:20",
                        "signal": -42,
                        "ssid": "Kept",
                        "phy": "IEEE802.11",
                        "type": "Wi-Fi AP",
                    }
                ]

        notes: list[tuple[str, str]] = []
        flute._log_hook = lambda msg, level: notes.append((level, msg))
        client = Client()
        devices = flute.fetch_recent_devices(client, 10)
        self.assertEqual(devices[0]["ssid"], "Kept")
        self.assertEqual(devices[0]["mac"], "AA:BB:CC:DD:EE:20")
        self.assertEqual(len(client.payloads), 2)
        self.assertEqual(flute._live_field_index, 1)
        self.assertTrue(any("device-name" in msg for _level, msg in notes))
        again = flute.fetch_recent_devices(client, 10)
        self.assertEqual(again[0]["ssid"], "Kept")
        self.assertEqual(len(client.payloads), 3)
        self.assertNotIn("name", {item[1] for item in client.payloads[-1]})

    def test_timeout_does_not_drop_name_fields(self) -> None:
        class Client:
            def post_json(self, path: str, payload: dict, timeout: float = 2.5) -> list:
                raise urllib.error.URLError("timed out")

        with self.assertRaises(urllib.error.URLError):
            flute.fetch_recent_devices(Client(), 1)
        self.assertEqual(flute._live_field_index, 0)


class RegressionTests(unittest.TestCase):
    def test_hop_rate_distance_and_channel_frequency(self) -> None:
        self.assertEqual(flute.parse_hop_rate("5"), 5)
        self.assertEqual(flute.parse_hop_rate("5/sec"), 5)
        self.assertEqual(flute.hop_dwell_ms(5), 200)
        with self.assertRaises(ValueError):
            flute.parse_hop_rate("0")
        self.assertIsNone(flute.estimate_distance_m(0, 2437, 20))
        self.assertGreater(flute.estimate_distance_m(-40, 2437, 20) or 0, 0)
        self.assertEqual(flute.format_dbm(0), "")
        self.assertEqual(flute.format_dbm(-40), "-40")
        self.assertEqual(flute.frequency_mhz_for_range(0, 48, "unspecified"), 5240.0)
        self.assertEqual(flute.frequency_mhz_for_range(0, 149, "unspecified"), 5745.0)
        self.assertIsNone(flute.frequency_mhz_for_range(0, "", "unspecified"))

    def test_full_device_keeps_advertised_tx_power(self) -> None:
        device = {
            "kismet.device.base.macaddr": "aa:bb:cc:dd:ee:30",
            "kismet.device.base.phyname": "IEEE802.11",
            "kismet.device.base.type": "Wi-Fi AP",
            "kismet.device.base.channel": "48",
            "kismet.device.base.frequency": 0,
            "kismet.device.base.name": "Front desk",
            "kismet.device.base.signal": {"kismet.common.signal.last_signal": -50},
            "dot11.device": {
                "dot11.device.last_beaconed_ssid_record": {
                    "dot11.advertisedssid.ssid": "Lab",
                    "dot11.advertisedssid.advertised_txpower": 12,
                }
            },
        }
        normalized = flute.normalize_live_device(device)
        self.assertEqual(normalized["tx_power"], 12)
        self.assertEqual(normalized["ssid"], "Lab")
        self.assertEqual(normalized["name"], "Front desk")
        self.assertEqual(normalized["mac"], "AA:BB:CC:DD:EE:30")

    def test_hop_log_skips_quiet_samples(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "flute_hop_log.csv"
            hop_log = flute.HopLog(path)
            device = {
                "mac": "AA:BB:CC:DD:EE:02",
                "phy": "IEEE802.11",
                "type": "Wi-Fi AP",
                "ssid": "Lab",
                "channel": "6",
                "frequency": 2437000,
                "signal": -40,
                "signal_min": -50,
                "signal_max": -30,
                "last_time": 10,
                "packets": 3,
                "tx_power": 20,
            }
            self.assertEqual(hop_log.append_sample([device]), 1)
            self.assertEqual(hop_log.append_sample([dict(device)]), 0)
            changed = dict(device)
            changed["signal"] = -41
            changed["packets"] = 4
            self.assertEqual(hop_log.append_sample([changed]), 1)
            self.assertEqual(hop_log.hop, 3)
            self.assertEqual(hop_log.rows, 2)
            hop_log.close()
            text = path.read_text(encoding="utf-8")
        self.assertIn("AA:BB:CC:DD:EE:02", text)
        hops = [line.split(",", 1)[0] for line in text.splitlines()[1:]]
        self.assertEqual(hops, ["1", "3"])

    def test_text_status_line_and_non_tty_capture(self) -> None:
        class Proc:
            returncode = None

            def poll(self) -> None:
                return None

        class Client:
            def get_json(self, path: str) -> object:
                if path == "/system/status.json":
                    return {
                        "kismet.system.devices.count": 4,
                        "kismet.system.packets.rrd": {
                            "kismet.common.rrd.last_value": 8
                        },
                    }
                if path == "/gps/all_gps.json":
                    return []
                if path == "/gps/location.json":
                    return {
                        "kismet.common.location.lat": 33.4,
                        "kismet.common.location.lon": -81.7,
                        "kismet.common.location.fix": "3D",
                    }
                if path == "/phy/all_phys.json":
                    return [
                        {"kismet.phy.name": "IEEE802.11", "kismet.phy.devices": 4}
                    ]
                raise AssertionError(path)

            def post_json(self, path: str, payload: dict, timeout: float = 2.5) -> list:
                return [
                    {
                        "mac": "aa:bb:cc:dd:ee:40",
                        "signal": -44,
                        "phy": "IEEE802.11",
                        "type": "Wi-Fi AP",
                        "ssid": "Lab",
                        "channel": "6",
                        "frequency": 2437000,
                        "last_time": 10,
                        "packets": 2,
                        "tx_power": 18,
                    }
                ]

        with tempfile.TemporaryDirectory() as tmp:
            hop_log = flute.HopLog(Path(tmp) / "flute_hop_log.csv")
            buffer = io.StringIO()
            stdout = sys.stdout
            sys.stdout = buffer
            try:
                flute.capture_loop(
                    Client(),
                    Proc(),
                    1,
                    hop_log=hop_log,
                    hop_rate=20,
                    survey={"userid": "jsmith", "test_name": "Lab"},
                    use_tui=True,
                )
            finally:
                sys.stdout = stdout
                hop_log.close()
            text = buffer.getvalue()
        self.assertIn("t=0s  GPS 33.400000,-81.700000 fix=3D  devices IEEE802.11=4", text)
        self.assertIn("hop=", text)
        self.assertIn("Duration reached; stopping capture.", text)
        self.assertNotIn("Live display could not start", text)
        self.assertGreaterEqual(hop_log.hop, 1)


class HelpAndCursesTests(unittest.TestCase):
    def test_help_lists_no_tui(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(ROOT / "flute.py"), "--help"],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--no-tui", proc.stdout)
        self.assertIn("--self-test", proc.stdout)

    def test_curses_paint_on_a_pty(self) -> None:
        script = r"""
import curses, os, sys
sys.path.insert(0, os.environ["FLUTE_ROOT"])
import flute
view = flute.DashboardView(
    userid="jsmith",
    operator_name="Jane Doe",
    test_name="Warehouse 4",
    host="survey-host",
    gps_text="33.400000,-81.700000 fix=3D",
    hops=12,
    devices_found=3,
    in_range=1,
    wifi_iface="mt7921-0",
    wifi_hint="Panda USB / MediaTek",
    bluetooth="hci0",
    devices=[{
        "mac": "AA:BB:CC:DD:EE:01",
        "signal": -33,
        "phy": "IEEE802.11",
        "type": "Wi-Fi AP",
        "ssid": "LabNet",
        "channel": "6",
        "frequency": 2437000,
        "tx_power": 20,
    }],
)
def run(stdscr):
    flute.init_dashboard_theme()
    stdscr.bkgd(" ", flute.dashboard_attr("fg"))
    flute.paint_dashboard(stdscr, view)
    stdscr.refresh()
    row = stdscr.instr(0, 0, min(80, stdscr.getmaxyx()[1])).decode("utf-8", "replace")
    sys.stderr.write(row + "\n")
curses.wrapper(run)
sys.stdout.write("painted\n")
"""
        master, slave = pty.openpty()
        stderr = b""
        try:
            winsize = struct.pack("HHHH", 24, 80, 0, 0)
            fcntl.ioctl(slave, termios.TIOCSWINSZ, winsize)
            env = os.environ.copy()
            env["TERM"] = "xterm-256color"
            env["FLUTE_ROOT"] = str(ROOT)
            proc = subprocess.Popen(
                [sys.executable, "-c", script],
                stdin=slave,
                stdout=slave,
                stderr=subprocess.PIPE,
                env=env,
            )
            os.close(slave)
            slave = -1
            pipe = proc.stderr
            stderr = pipe.read() if pipe is not None else b""
            if pipe is not None:
                pipe.close()
            proc.wait(timeout=20)
        finally:
            if slave >= 0:
                os.close(slave)
            os.close(master)
        self.assertEqual(proc.returncode, 0, stderr.decode("utf-8", "replace"))
        err = stderr.decode("utf-8", "replace")
        self.assertIn("MAGIC", err)


if __name__ == "__main__":
    unittest.main()
