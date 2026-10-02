# The Magic Flute

Passive Wi-Fi / Bluetooth survey using [Kismet](https://www.kismetwireless.net/).

The program file is **`flute.py`**. 

Named after Mozart’s *Die Zauberflöte*, inspired by the moment when two of the main characters find each other by playing flutes.
YES, I am a nerd!

Download it, attach a monitor-capable Wi-Fi adapter (and optionally Bluetooth + a USB GPS), run `--setup`, and collect receive-only observations with GPS tags.

Python 3.9+ stdlib only. No `pip` packages. Licensed under **GPL-3.0-or-later**.

On each capture (and on `--check` / `--setup`) the tool looks for vendor files next to `flute.py`:

- `ieee_mac_vendors.csv` — IEEE MAC prefixes (MA-L, MA-M, MA-S, and IAB)
- `bt_company_ids.csv` — Bluetooth SIG 16-bit company identifiers (used only when a BLE advertisement contains manufacturer data, AD type `0xFF`)

If either file is **missing** or **older than 180 days**, it **asks** whether to download a refresh (a few megabytes). The default is **no**, so an air-gapped host can continue without internet.

**A second IEEE prefix file will not fill in most Bluetooth manufacturers.** Modern BLE devices use *random/private addresses* (resolvable, non-resolvable, or static random). Those MACs are not IEEE OUIs, so no prefix registry can map them.

What *does* identify an iPhone vs a Galaxy vs a Moto on a random BLE MAC is the **advertisement payload**: Bluetooth SIG company ID `0xFF` (Apple `0x004C`, Samsung `0x0075`, Motorola `0x0008`, Microsoft `0x0006`, Google `0x00E0`) and a few 16-bit UUIDs (Google Fast Pair `0xFE2C`). Kismet’s Linux HCI helper sees those bytes and **throws them away** — it only keeps the device name. The Magic Flute therefore:

1. Looks up public / universally administered MACs in the IEEE file.
2. Taps the same BlueZ management `DEVICE_FOUND` events Kismet uses and keeps the EIR (written to `ble_advertisements.jsonl`).
3. Maps company ID `0xFF` through the SIG list (or Kismet’s `kismet_bluetooth_manuf.txt.gz`).
4. Treats Fast Pair / Eddystone UUIDs as Android-class, not a specific OEM.
5. Infers a vendor from an advertised name when it is unambiguous (Govee, LG webOS, Galaxy, iPhone, Moto, …).
6. Copies a vendor onto a BLE sibling that shares the last five octets of a public BR/EDR MAC.
7. Labels the rest `Random BLE address` or `Locally administered MAC` instead of guessing.

The advertisement tap needs the same root/`cap_net_admin` Flute already uses. It does **not** pair, connect, or enumerate GATT. Captures taken before this tap have no EIR to replay; `--report-from` only helps if `ble_advertisements.jsonl` is in that directory.

Google Fast Pair means “Android-class device” (Samsung, Motorola, Pixel, and many headphones). It does **not** name the OEM. Apple Continuity (`0x004C`) is the reliable iPhone/iPad/AirPods tell. Many phones send no name and no company ID; those stay `Random BLE address`.

Non-interactive:

- `--download-ieee` — fetch IEEE + SIG files without asking (needs internet)
- `--no-download-ieee` — never fetch; use the files on disk if any
- `--report-from DIR` — rebuild reports from an existing capture (re-applies lookups; no new survey)

## Disclaimer — authorized use only

**The Magic Flute records radio emissions:** MAC addresses, SSIDs, signal levels, advertised names, and (if a GPS is attached) the surveyor’s coordinates.

Use it **only** where you have legal authority, for example:

- a signed Rules of Engagement (ROE)
- written permission from the network/property owner or client
- your own equipment and premises
- another lawful basis that applies where you are

Unauthorized interception of communications can be a crime. You are responsible for local law. The authors assume **no liability** for misuse.

The collector is **receive-only**. It does not inject packets, deauthenticate clients, associate to networks, pair with Bluetooth devices, or guess credentials.

Collection starts only after you type `YES` (interactive) or pass `--i-have-roe` (non-interactive). That acknowledgement is stored with the reports.

## What it is for

Walk an authorized area and record what the radios can hear:

| Goal                                | How this collection helps                                              |
| ----------------------------------- | ---------------------------------------------------------------------- |
| Unexpected / spurious transmissions | SSIDs, BSSIDs, and Bluetooth advertisers that should not be on the air |
| Unauthorized wireless devices       | MAC addresses and advertised names not on an approved inventory        |
| Devices outside an allowed area     | GPS on each device plus a GPS track of the surveyor                    |

## Hardware

Any Linux host with:

| Role           | What works                        | Notes                                                                                                                                          |
| -------------- | --------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Wi-Fi          | USB adapter with **monitor mode** | Preferred. MediaTek mt76 / Panda-class (`mt7921u`, etc.) are well supported. Built-in Intel often works but is usually a poorer capture radio. |
| Bluetooth      | BlueZ `hci` and/or **Ubertooth One** | Built-in Intel is fine for names. An Ubertooth One sniffs BTLE advertisements (manufacturer IDs). `--setup` installs the helper, tools, and udev rules. |
| GPS (optional) | USB NMEA receiver                 | GlobalSat BU-353S4 (Prolific `067b:2303`) is autodetected at 4800 baud. Other NMEA USB GPSes on `/dev/ttyUSB*` or `/dev/ttyACM*` work too.     |

The script lists whatever is plugged in and lets you pick. You do not have to use this exact hardware.

## Quick start

```bash
git clone <your-repo-url> flute
cd flute

# Install Kismet, Ubertooth helper/tools/udev, groups, capabilities
sudo python3 flute.py --setup
# log out and back in if groups were added

# See what the machine has
python3 flute.py --check

# Authorized capture (you will be asked to type YES)
sudo python3 flute.py
```

`--setup` uses `apt`, `dnf`, or `pacman` depending on the distro. On Pop!_OS, Ubuntu, and Debian, Kismet is often **not** in the default repos; setup adds the [official Kismet apt repository](https://www.kismetwireless.net/packages/) (release, then git/nightly if needed), then installs `kismet` plus `iw`, `rfkill`, `gpsd`, and (when the packages exist) `kismet-capture-ubertooth-one`, `ubertooth`, and `ubertooth-firmware`. It also writes `/etc/udev/rules.d/99-flute-ubertooth.rules` so the Ubertooth USB device is `0660` for the `kismet` group.

Do **not** run `ubertooth-util -i` on Ubuntu’s package — that flag enters ISP/DFU mode. Setup uses `ubertooth-util -v` only. If the stick shows USB id `1d50:6003`, unplug and re-insert it.

## What `--setup` and each capture do

Lessons from field use are built in:

| Step                                                        | Why                                                                 |
| ----------------------------------------------------------- | ------------------------------------------------------------------- |
| Install Kismet + `kismet_cap_linux_wifi` / `linuxbluetooth` / `ubertooth_one` | Capture helpers |
| `setcap cap_net_admin,cap_net_raw` on the Linux Wi-Fi/HCI helpers | Monitor mode without full root |
| Add the login user to `kismet`, `dialout`, and `plugdev`    | Helpers + USB GPS + Ubertooth USB |
| Ubertooth udev rule `99-flute-ubertooth.rules`              | Non-root can claim the sniffer (`1d50:6002`) |
| `rfkill unblock` wifi and bluetooth                         | Soft-blocked radios (common on laptops) look like “no signal”       |
| Remove leftover `kismon*` monitor interfaces                | A previous run can leave a VAP that needs root to delete            |
| Unmanage **only** the chosen Wi-Fi iface in NetworkManager  | Ethernet stays up                                                   |
| Write Kismet’s HTTP password under `$HOME/.kismet/`         | Live status / localhost UI                                          |
| Skip GPS if the serial node is unreadable                   | Don’t hang Kismet; tell you to run `--setup` or sudo                |
| Use **gpsd** when the puck speaks SiRF binary               | GlobalSat BU-353S4 often is not NMEA; Kismet serial cannot parse it |
| Offer to refresh IEEE MAC vendors + BT SIG IDs if missing or >180 days | Asks first (default no) so air-gapped hosts are not blocked |
| Label random BLE / locally administered MACs honestly       | Extra OUI files cannot identify privacy addresses                   |
| Tap BlueZ `DEVICE_FOUND` EIR while Kismet runs              | Kismet HCI drops company IDs; this is how Apple/Samsung/Moto show up |
| Restore the Wi-Fi iface when the run ends                   | Laptop networking comes back                                        |

A hardware airplane/kill switch (**hard** rfkill) cannot be overridden. Flip the switch.

## What is collected (passive)

For each observed device:

- MAC address
- SSID (beaconed) and probed SSIDs, when present
- Signal strength (last / min / max dBm)
- Frequency and channel
- GPS coordinates (last / average / min-max), when a GPS has a fix
- Advertised machine names (Kismet name, DHCP hostname, WPS device name, Bluetooth local name)

Wi-Fi is **monitor mode, receive only**. The radio listens continuously on the current channel; it does **not** run periodic `iw scan` polls. Kismet hops channels at a configurable rate (default **5 hops per second**, 200 ms on each channel).

Bluetooth uses Kismet’s `linuxbluetooth` datasource. BLE advertisements are observed from the air. Classic Bluetooth discovery uses the adapter’s HCI inquiry (a standard controller scan, not a targeted attack) and **does not pair or connect**. Use `--no-bluetooth` if even HCI inquiry is out of scope.

## GPS (GlobalSat BU-353S4 and similar)

Kismet’s serial driver understands **NMEA only**. Many BU-353S4 units (SiRF Star IV) speak **SiRF binary** on `/dev/ttyUSB0` at 4800 baud. Ubuntu/Pop!_OS also often run **systemd `gpsd.socket`**, which listens on port 2947 with **no GPS attached**. If The Magic Flute assumed that empty socket was enough, Kismet would sit on `GPS connected, searching` forever.

The Magic Flute now attaches `/dev/ttyUSB0` to gpsd (`gpsdctl add`, or starts gpsd itself) and points Kismet at `gps=gpsd:host=localhost,port=2947`. `--setup` installs `gpsd` and `gpsd-clients`.

Even with gpsd, a cold start needs satellites:

- Outdoors, clear sky: often 30–60 seconds.
- Indoors, second story, through a roof: minutes, a weak 2D fix, or never.
- Put the puck on a windowsill with a view of the sky. The BU-353S4 LED typically **blinks faster once it has a fix**.

The live line is:

- `GPS 33.4…,-81.7…` — real fix
- `GPS searching (N sats)` — gpsd sees the puck; waiting on satellites
- `GPS receiver up, 0 sats` — USB is open but no satellites yet (window/sky)
- `GPS not connected` — Kismet/gpsd did not attach a GPS

## Channel hop rate

This is how often the Wi-Fi adapter **changes channel**. Packets are captured the whole time it dwells on a channel.

| Hops per second   | Dwell per channel | Typical use                            |
| ----------------- | -----------------:| -------------------------------------- |
| `1`               | 1000 ms           | Slow walk, more packets per channel    |
| `2`               | 500 ms            | Indoor survey                          |
| **`5` (default)** | **200 ms**        | Walking survey (Kismet’s own default)  |
| `10`              | 100 ms            | Faster sweep, fewer frames per channel |

Interactive runs ask after UserID / name / test name. Non-interactive runs take `--hop-rate`. Range is 1–20.

The on-screen GPS/device counter refreshes every 5 seconds. That is status only, not RF sampling.

## Usage

Interactive:

```bash
sudo python3 flute.py
```

At start the script:

1. Prints the authorized-use disclaimer. Type `YES` only if you have lawful authorization.
2. Unblocks radios and cleans leftover monitor interfaces.
3. If `ieee_mac_vendors.csv` or `bt_company_ids.csv` is missing or older than 180 days, asks whether to download them (default **no**; needs internet if you say yes).
4. Lists wireless controllers and asks you to pick one (USB monitor-capable adapters are marked recommended).
5. Lists Bluetooth controllers and asks you to pick one (or skip).
6. Autodetects a USB NMEA GPS.
7. Asks for **UserID** (e.g. your username or employee ID), **operator name**, and **test name** (e.g. `Warehouse 4 north wing`).
8. Asks for **channel hop rate** (default `5`).
9. Unmanages the chosen Wi-Fi interface from NetworkManager and starts Kismet.
10. Prints GPS / device counts every 5 seconds. Press **Ctrl-C** to stop, or use `--duration`.
11. Finalizes the `.kismet` log and writes reports, including `ieee_manufacturer`, `mac_kind`, `bt_company`, and `bt_uuids`.

Live UI (localhost only): http://127.0.0.1:2501

Non-interactive:

```bash
sudo python3 flute.py \
  --i-have-roe \
  --userid jsmith \
  --operator-name "Jane Doe" \
  --test-name "Warehouse 4 north wing" \
  --wifi wlx9cefd5f63b21 \
  --bluetooth hci0 \
  --hop-rate 5 \
  --no-download-ieee \
  --duration 1800
```

Replace `wlx9cefd5f63b21` with the interface `--check` or `--list-only` reports.

```bash
python3 flute.py --list-only
python3 flute.py --check
```

Dry run (still requires authorization acknowledgement; does not start Kismet):

```bash
sudo python3 flute.py \
  --i-have-roe \
  --userid jsmith \
  --operator-name "Jane Doe" \
  --test-name "Lab check" \
  --wifi wlx9cefd5f63b21 \
  --no-bluetooth \
  --no-gps \
  --hop-rate 5 \
  --dry-run
```

## Options

| Flag                                            | Meaning                                                                  |
| ----------------------------------------------- | ------------------------------------------------------------------------ |
| `--setup`                                       | Install packages, groups, and capabilities (needs sudo)                  |
| `--check`                                       | Print environment + hardware; do not capture                             |
| `--download-ieee`                               | Download/refresh IEEE prefixes + Bluetooth SIG company IDs (needs internet) |
| `--no-download-ieee`                            | Do not download vendor files (offline / air-gapped)                      |
| `--report-from DIR`                             | Rebuild reports from an existing capture directory (no new survey)       |
| `--i-have-roe`                                  | Confirm signed ROE / written authorization (required when not a TTY)     |
| `--userid`                                      | Operator user ID (username or employee ID)                               |
| `--operator-name NAME`                          | Operator full name                                                       |
| `--test-name NAME`                              | Test / location name                                                     |
| `--hop-rate N`                                  | Wi-Fi channel hops per second (default `5` = 200 ms/channel; range 1–20) |
| `--wifi IFACE`                                  | Skip the Wi-Fi picker                                                    |
| `--bluetooth hci0` / `--bluetooth ubertooth-0`  | Skip the Bluetooth picker. Ubertooth also enables HCI unless `--no-hci`. |
| `--no-hci`                                      | Do not add Linux HCI when Ubertooth is selected                          |
| `--no-bluetooth`                                | Wi-Fi only                                                               |
| `--gps-device /dev/ttyUSB0` / `--gps-baud 4800` | Override GPS                                                             |
| `--no-gps`                                      | Do not attach GPS                                                        |
| `--duration N`                                  | Stop after N seconds                                                     |
| `-o DIR`                                        | Output directory (default `./flute_<timestamp>`)                         |
| `--pcap`                                        | Also write pcapng / packet log (large)                                   |
| `--hide-data`                                   | Truncate 802.11 data payloads                                            |
| `--http-port 2501`                              | Kismet web port (bound to 127.0.0.1)                                     |
| `--list-only`                                   | Print controllers and GPS, then exit                                     |
| `--dry-run`                                     | Print the capture plan and exit                                          |

## Outputs

Default directory: `flute_YYYYMMDDTHHMMSSZ/`

| File                    | Contents                                                                        |
| ----------------------- | ------------------------------------------------------------------------------- |
| `operator_session.json` | UserID, name, test name, hop rate, authorization acknowledgement, adapters, GPS |
| `flute_report.json`     | Full structured result                                                          |
| `flute_report.txt`      | Human-readable report                                                           |
| `flute_report.md`       | Markdown report                                                                 |
| `flute_devices.csv`     | Every device (MAC, SSID, `ieee_manufacturer`, `mac_kind`, `bt_company`, `bt_uuids`, signal, frequency, GPS, names, `closest_m`, `furthest_m`) |
| `ble_advertisements.jsonl` | Raw BLE AD/EIR from the BlueZ tap (company IDs, UUIDs). Empty if the tap could not bind. |
| `flute_wifi.csv`        | Wi-Fi subset (same columns, including `closest_m` and `furthest_m`)            |
| `flute_bluetooth.csv`   | Bluetooth subset (same columns, including `closest_m` and `furthest_m`)        |
| `flute_hop_log.csv`     | Devices whose packets, signal, or last-heard time changed on a sample. The `hop` column skips samples with no change. Appended and synced during the capture so a crash keeps completed samples. |
| `flute_gps_track.csv`   | Surveyor track (when a fix existed)                                             |
| `*.kismet`              | Native Kismet database                                                          |
| `kismet_server.log`     | Kismet stdout                                                                   |

Do not commit capture output. Indoor GPS can take minutes or fail; the script keeps collecting and leaves coordinates empty until there is a fix.

## Hop log

`flute_hop_log.csv` is opened when Kismet comes up. The script polls Kismet once per channel dwell (the hop rate, default 5/sec, so a poll is scheduled every 200 ms). Each poll increments a sample counter named `hop`, whether or not anything is written. `hop` is that counter. It is not a row number, not a Wi-Fi channel, and not a counter read back from Kismet.

A poll writes rows only for devices that changed, then flushes and `fsync`s those rows. A crash, `SIGTERM`, or Ctrl-C keeps every sample that wrote rows. A poll with nothing new writes nothing and does not sync. The summary CSVs and the text report are still written at the end of a clean stop.

Because quiet polls are omitted, the numbers in the file skip. A `hop` column that reads `2, 4, 9, 20, 38` is the normal result:

- Sample 1 ran and Kismet had not returned a device yet, so the file starts at 2.
- Samples 3, 5–8, and 10–19 ran. Every MAC already in the log still had the same packet count, signal, and last-heard time, so those samples added no rows.
- Samples 2, 4, 9, 20, and 38 each had at least one new or changed device.

Several devices that change on the same poll share that `hop` number and the same `timestamp` (UTC, from this computer's clock, millisecond resolution). Three devices changing on sample 20 produce three rows, all with `hop` 20.

A device is written when its packet count, last signal, strongest or weakest signal, or last-heard time differs from the last row stored for that MAC. The first time a MAC is seen, that counts as a change. A radio that stays quiet, or that keeps beaconing with the same signal and the same packet count, is not repeated on later polls.

Kismet's last-heard clock is one-second resolution. A steady transmitter is often logged about once a second, when that clock ticks, rather than on every 200 ms poll. A change of 1 dB in the signal logs it on the poll that saw the change. Asking Kismet over HTTP takes longer than the dwell on a busy host, so the real poll rate is often a little under the requested hop rate. That stretches the clock time between sample numbers. It does not drop sample numbers; the gaps in the file are the quiet polls.

| Column | Meaning |
| --- | --- |
| `hop` | Sample number since capture start, from 1. Increments on every poll, including polls that write no rows, so the values in the file skip |
| `timestamp` | UTC time of that sample. Shared by every row written from the same poll |
| `mac` | Device MAC that was new or had changed on that sample |
| `phy`, `type`, `ssid`, `channel` | What Kismet had for the device |
| `frequency_mhz` | Frequency used for the distance estimate |
| `signal_dbm` | Signal on that sample, dBm. Blank when Kismet has no dBm sample (it reports `0`) |
| `distance_m` | Rough range in meters. Blank when `signal_dbm` is blank |
| `tx_dbm` | Transmit power used in the formula. The AP's advertised power when it sends one, otherwise the assumed power below |
| `path_loss_exponent` | `2.7` for every row |

`--report-from` rebuilds `closest_m` and `furthest_m` from the Kismet database. It cannot rebuild `flute_hop_log.csv`. That history only exists if it was written during the capture.

## Distance estimate

Signal level and distance are **not** linear. Received power in milliwatts falls off roughly with the square of distance in open air, which is a straight line only when you plot dBm against the logarithm of distance. The estimate uses the log-distance path loss model:

```
RSSI = TX - FSPL(1 m) - 10 * n * log10(d)
d    = 10 ^ ((TX - FSPL(1 m) - RSSI) / (10 * n))
FSPL(1 m) = 20 * log10(f_MHz) - 27.55
```

`n` is the path loss exponent. `n = 2` is free space (the inverse-square law). Indoors, with walls and bodies, `n` is usually somewhere from 2.7 to 4. Every distance in this tool uses **`n = 2.7`**, a rough middle for a walking survey. It is not a calibrated range.

Assumed transmit power, used only when the device does not advertise one:

| Radio | Assumed TX |
| --- | ---: |
| Wi-Fi AP, or any non-client beaconing an SSID | 20 dBm |
| Other Wi-Fi | 15 dBm |
| Bluetooth classic (BR/EDR, Class 2) | 4 dBm |
| BLE | 0 dBm |

`closest_m` on the device CSVs is this formula applied to the **strongest** signal (`signal_max_dbm`). `furthest_m` uses the **weakest** (`signal_min_dbm`). They sit next to `first_seen` and `last_seen`: first/last are the time extremes, closest/furthest are the distance extremes. The text and Markdown reports are otherwise unchanged.

A 10 dB error (ordinary multipath, or a phone that is not actually transmitting at the assumed power) scales the distance by about 2.3× at `n = 2.7`. Read `distance_m` as near / mid / far, not as a tape measure. Moving the antenna a few centimeters can change the reading.

## Troubleshooting

| Symptom                                      | What to check                                                                         |
| -------------------------------------------- | ------------------------------------------------------------------------------------- |
| Missing Kismet / helpers                     | `sudo python3 flute.py --setup` (adds the official Kismet apt repo on Ubuntu/Pop/Debian) |
| `Unable to locate package kismet`            | Distro repos lack Kismet. Re-run `--setup` (now adds kismetwireless.net) or see https://www.kismetwireless.net/packages/ |
| Not in `kismet` or `dialout`                 | `--setup`, then **log out and back in**                                               |
| No wireless controllers                      | USB adapter seated; `python3 flute.py --check`                                        |
| Empty Wi-Fi results                          | Monitor mode? `rfkill list`; pick the USB adapter, not a client-only dongle           |
| GPS missing / permission denied              | `ls -l /dev/ttyUSB0`; `--setup` for dialout, or `sudo`; baud 4800                     |
| GPS “binary data, not NMEA” / no-fix forever | BU-353S4 in SiRF mode. `sudo python3 flute.py --setup` (installs gpsd) and re-run     |
| GPS connected / searching, never a fix       | Empty systemd `gpsd.socket` used to cause this. Update `flute.py` and re-run with sudo. Put the puck on a windowsill. |
| Leftover `kismon0`                           | `sudo iw dev kismon0 del` (the script tries; deleting a VAP needs net-admin)          |
| Port 2501 in use                             | Another Kismet is running. Stop it or pass `--http-port`                              |
| Bluetooth empty                              | `rfkill unblock bluetooth`; or `--no-bluetooth`                                       |
| Ubertooth not listed / USB permission        | `sudo python3 flute.py --setup`, unplug/replug. Do not run `ubertooth-util -i` (ISP). |
| Ubertooth USB id `1d50:6003`                 | DFU/ISP mode. Unplug and re-insert. Flash only if it stays there (`ubertooth-firmware`). |
| Ubertooth finds few devices                  | It sniffs **channel 37 only** (firmware hangs if hopped). HCI still sees names on all ads. |
| `--bluetooth ubertooth-0` shows 0 Bluetooth devices | Kismet launched Ubertooth but **dropped CRC-fail packets** (228 frames in the Cyber Lab run, 0 devices). Host libubertooth is API 1.06, stick firmware is 1.07. Flute now also enables Linux HCI unless you pass `--no-hci`. Re-run: `sudo python3 flute.py --bluetooth ubertooth-0` |
| Hardware rfkill                              | Flip the airplane / wireless kill switch                                              |
| IEEE vendor file missing / stale             | You will be asked before any download (default no). Use `--download-ieee` online, or `--no-download-ieee` offline |
| Bluetooth `ieee_manufacturer` is Unknown / Random BLE address | Expected when the device sent no name and no manufacturer AD. Another MAC-prefix file will not help. Re-run a survey with current `flute.py` as root so the BlueZ EIR tap can see Apple `0x004C` / Samsung `0x0075` / Fast Pair. Old captures have no EIR to replay. |

## License

The Magic Flute is free software under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE) for the full terms.

You may run, share, and modify it. If you distribute this program or a modified version, you must keep it under the GPL and provide the corresponding source. There is **no warranty**.

Kismet, which this tool launches, is separately licensed by its authors (also GPL). Their terms apply to Kismet itself.

The GPL covers copyright of the software. It does **not** authorize wireless collection. You still need lawful authority (ROE or equivalent) before you run a survey.

## Repository contents

```
flute.py               # setup, checks, Kismet launcher, reports (GPL-3.0-or-later)
ieee_mac_vendors.csv   # IEEE OUI cache (optional download; not in git)
bt_company_ids.csv     # Bluetooth SIG company IDs (optional download; not in git)
README.md
LICENSE                # GNU GPL v3
.gitignore
```
