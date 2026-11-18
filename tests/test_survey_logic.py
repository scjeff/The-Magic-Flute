#!/usr/bin/env python3
"""Checks for distance, BLE identity, report split, and command timeouts.

No Kismet process and no radio. Synthetic frames only.

    python3 tests/test_survey_logic.py
    python3 flute.py --self-test
"""

from __future__ import annotations

import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import flute


AA = bytes.fromhex("d6be898e")
DEMO_MAC = "AA:BB:CC:DD:EE:FF"


def _air_addr(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))[::-1]


def _adv_packet(mac: str = DEMO_MAC) -> bytes:
    """10-byte LE RF header, access address, then ADV_IND with an Apple AD."""
    ad = bytes([0x04, 0xFF, 0x4C, 0x00, 0x10])
    payload = _air_addr(mac) + ad
    pdu = bytes([0x40, len(payload)]) + payload
    # Flags 0x0000 sit between the reference AA and the real packet AA.
    # A loose parser treats those two zero bytes as an ADV_IND header.
    header = bytes([37, 0xC4, 0x00, 0x00]) + AA + b"\x00\x00"
    return header + AA + pdu


def _radiotap_like() -> bytes:
    """Bytes that look like a monitor header, with no LE access address."""
    return bytes.fromhex("000032002f4000a0") + bytes([0x00, 0x20]) + b"\x11" * 30


class DistanceAndRadioTests(unittest.TestCase):
    def test_ten_db_scales_range_by_the_path_loss_exponent(self) -> None:
        near = flute.estimate_distance_m(-40, 2437, 20)
        far = flute.estimate_distance_m(-50, 2437, 20)
        self.assertIsNotNone(near)
        self.assertIsNotNone(far)
        self.assertAlmostEqual(far / near, 10 ** (1 / 2.7), places=6)

    def test_signal_zero_and_channel_only_frequency(self) -> None:
        self.assertIsNone(flute.estimate_distance_m(0, 2437, 20))
        self.assertEqual(flute.frequency_mhz_for_range(0, 1, "unspecified"), 2412.0)
        self.assertEqual(flute.frequency_mhz_for_range(0, 14, "unspecified"), 2484.0)
        self.assertEqual(flute.frequency_mhz_for_range(0, 36, "unspecified"), 5180.0)
        self.assertIsNone(flute.frequency_mhz_for_range(0, "", "unspecified"))

    def test_usbwifi_source_string(self) -> None:
        text = flute.wifi_source_definition(
            {"iface": "mt7921-0", "source_type": "usbwifi", "hint": "Panda"},
            5,
        )
        self.assertEqual(text, "mt7921-0:type=usbwifi,name=Panda,hop=true,hoprate=5/sec")

    def test_hop_log_uses_advertised_power_and_skips_signal_zero(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            hop_log = flute.HopLog(Path(tmp) / "flute_hop_log.csv")
            hop_log.append_sample(
                [
                    {
                        "mac": DEMO_MAC,
                        "phy": "IEEE802.11",
                        "type": "Wi-Fi AP",
                        "ssid": "Lab",
                        "channel": "6",
                        "frequency": 0,
                        "signal": 0,
                        "tx_power": 12,
                        "last_time": 1,
                        "packets": 1,
                    }
                ]
            )
            hop_log.close()
            row = (Path(tmp) / "flute_hop_log.csv").read_text(encoding="utf-8").splitlines()[1]
        self.assertIn(",6,2437.000,,", row)
        self.assertIn(",12.0,", row)

    def test_helper_timeout_returns_instead_of_raising(self) -> None:
        try:
            proc = flute.run_cmd(["sleep", "5"], timeout=1)
        except subprocess.TimeoutExpired as exc:
            self.fail(f"run_cmd raised TimeoutExpired: {exc}")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("timed out", proc.stderr)


class BluetoothIdentityTests(unittest.TestCase):
    def test_le_address_is_display_order_and_wifi_frames_are_ignored(self) -> None:
        parsed = flute.parse_ubertooth_or_btle_packet(_adv_packet())
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed["mac"], DEMO_MAC)
        self.assertEqual(parsed["company_ids"], [0x004C])
        self.assertEqual(parsed["apple_types"], ["Nearby Info"])
        self.assertIsNone(flute.parse_ubertooth_or_btle_packet(_radiotap_like()))
        disguised = b"\x00" * 14 + bytes([0x00, 0x06]) + _air_addr(DEMO_MAC)
        self.assertIsNone(flute.parse_ubertooth_or_btle_packet(disguised))

    def test_extractor_keeps_le_frames_and_drops_wifi(self) -> None:
        wifi_mac = "11:22:33:44:55:66"
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "sample.kismet"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE packets (packet BLOB, sourcemac TEXT, phyname TEXT, dlt INT)"
            )
            conn.execute(
                "INSERT INTO packets VALUES (?, ?, ?, ?)",
                (_adv_packet(), "00:00:00:00:00:00", "Unknown", 256),
            )
            conn.execute(
                "INSERT INTO packets VALUES (?, ?, ?, ?)",
                (_adv_packet(wifi_mac), wifi_mac, "IEEE802.11", 127),
            )
            conn.execute(
                "INSERT INTO packets VALUES (?, ?, ?, ?)",
                (_radiotap_like(), "22:33:44:55:66:77", "IEEE802.11", 127),
            )
            conn.commit()
            conn.close()
            found = flute.extract_btle_advertisements_from_db(db_path)
        self.assertEqual(list(found), [DEMO_MAC])
        self.assertNotIn(wifi_mac, found)
        self.assertEqual(found[DEMO_MAC]["company_ids"], [0x004C])

    def test_nrpa_without_an_oui_is_random_not_public(self) -> None:
        mac = "00:11:22:33:44:55"
        self.assertEqual(flute.classify_mac_kind(mac, "BTLE", "BTLE"), "ble-nrpa")
        devices = [{"mac": mac, "phy": "BTLE", "type": "BTLE"}]
        flute.apply_ieee_manufacturers(devices, {})
        self.assertEqual(devices[0]["mac_kind"], "ble-nrpa")
        self.assertEqual(devices[0]["ieee_manufacturer"], "Random BLE address")

    def test_nrpa_with_a_real_oui_stays_public(self) -> None:
        mac = "00:11:22:33:44:55"
        devices = [{"mac": mac, "phy": "Bluetooth", "type": "BTLE"}]
        flute.apply_ieee_manufacturers(devices, {"001122": "Example Vendor"})
        self.assertEqual(devices[0]["mac_kind"], "ble-public")
        self.assertEqual(devices[0]["ieee_manufacturer"], "Example Vendor")

    def test_btle_tracker_is_not_filed_as_wifi(self) -> None:
        devices = [
            {
                "mac": "AA:BB:CC:DD:EE:10",
                "phy": "BTLE",
                "type": "BTLE Tracker",
                "ssid": "",
                "ieee_manufacturer": "Random BLE address",
                "mac_kind": "ble-rpa",
            },
            {
                "mac": "AA:BB:CC:DD:EE:11",
                "phy": "IEEE802.11",
                "type": "Wi-Fi AP",
                "ssid": "Lab",
                "ieee_manufacturer": "Example Vendor",
                "mac_kind": "public",
            },
        ]
        summary = flute.summarize_devices(devices)
        self.assertEqual(summary["bluetooth"], 1)
        self.assertEqual(summary["wifi"], 1)
        with tempfile.TemporaryDirectory() as tmp:
            flute.write_reports(
                Path(tmp),
                {"devices": devices, "summary": summary, "session": {}, "gps_track": []},
            )
            wifi = (Path(tmp) / "flute_wifi.csv").read_text(encoding="utf-8")
            bluetooth = (Path(tmp) / "flute_bluetooth.csv").read_text(encoding="utf-8")
        self.assertIn("AA:BB:CC:DD:EE:10", bluetooth)
        self.assertNotIn("AA:BB:CC:DD:EE:10", wifi)
        self.assertIn("AA:BB:CC:DD:EE:11", wifi)
        self.assertNotIn("AA:BB:CC:DD:EE:11", bluetooth)

    def test_report_from_rebuilds_channel_frequency_without_a_hop_log(self) -> None:
        devjson = (
            '{"kismet.device.base.phyname":"IEEE802.11",'
            '"kismet.device.base.type":"Wi-Fi AP",'
            '"kismet.device.base.macaddr":"AA:BB:CC:DD:EE:20",'
            '"kismet.device.base.channel":"149",'
            '"kismet.device.base.frequency":0,'
            '"kismet.device.base.signal":{'
            '"kismet.common.signal.last_signal":-40,'
            '"kismet.common.signal.min_signal":-70,'
            '"kismet.common.signal.max_signal":-40},'
            '"dot11.device":{"dot11.device.last_beaconed_ssid_record":{'
            '"dot11.advertisedssid.ssid":"Lab",'
            '"dot11.advertisedssid.crypt_string":"WPA2-PSK",'
            '"dot11.advertisedssid.advertised_txpower":12}}}'
        )
        with tempfile.TemporaryDirectory() as tmp:
            outdir = Path(tmp)
            db_path = outdir / "sample.kismet"
            conn = sqlite3.connect(db_path)
            conn.execute(
                "CREATE TABLE devices ("
                "first_time INT, last_time INT, phyname TEXT, devmac TEXT, "
                "strongest_signal INT, min_lat REAL, min_lon REAL, max_lat REAL, "
                "max_lon REAL, avg_lat REAL, avg_lon REAL, bytes_data INT, "
                "type TEXT, device TEXT)"
            )
            conn.execute(
                "INSERT INTO devices VALUES (1, 2, 'IEEE802.11', ?, -40, "
                "NULL, NULL, NULL, NULL, NULL, NULL, 0, 'Wi-Fi AP', ?)",
                ("AA:BB:CC:DD:EE:20", devjson),
            )
            conn.commit()
            conn.close()
            code = flute.reprocess_outdir(outdir, "no")
            self.assertEqual(code, 0)
            self.assertFalse((outdir / "flute_hop_log.csv").exists())
            csv_text = (outdir / "flute_devices.csv").read_text(encoding="utf-8")
            report = (outdir / "flute_report.txt").read_text(encoding="utf-8")
        self.assertIn("5745.000", csv_text)
        self.assertIn("WPA2-PSK", csv_text)
        self.assertRegex(csv_text, r"\d+\.\d+,\d+\.\d+")
        self.assertNotIn("closest_m", report)
        self.assertNotIn("furthest_m", report)


if __name__ == "__main__":
    unittest.main()
