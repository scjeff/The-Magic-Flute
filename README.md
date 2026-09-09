# The Magic Flute

Passive Wi-Fi / Bluetooth survey using [Kismet](https://www.kismetwireless.net/).

The program file is **`flute.py`**. 

Named after Mozart’s *Die Zauberflöte*

Download it, attach a monitor-capable Wi-Fi adapter (and optionally Bluetooth + a USB GPS), run `--setup`, and collect receive-only observations with GPS tags.

Python 3.9+ stdlib only. No `pip` packages. Licensed under **GPL-3.0-or-later**.

On each capture (and on `--check` / `--setup`) the tool looks for an IEEE MAC vendor file (`ieee_mac_vendors.csv`) next to `flute.py`. If that file is **missing** or **older than 180 days**, it **asks** whether to download a fresh copy from IEEE (MA-L + MA-M + MA-S, a few megabytes). The default is **no**, so an air-gapped host can continue without internet. If you decline and no file is present, `ieee_manufacturer` is **Unknown**. When the survey stops (Ctrl-C or `--duration`), every MAC is matched to whatever registry is on disk.

Non-interactive:

- `--download-ieee` — fetch without asking (needs internet)
- `--no-download-ieee` — never fetch; use the file on disk if any

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
| Bluetooth      | Any BlueZ `hci` controller        | Built-in Intel AX-series is fine.                                                                                                              |
| GPS (optional) | USB NMEA receiver                 | GlobalSat BU-353S4 (Prolific `067b:2303`) is autodetected at 4800 baud. Other NMEA USB GPSes on `/dev/ttyUSB*` or `/dev/ttyACM*` work too.     |

The script lists whatever is plugged in and lets you pick. You do not have to use this exact hardware.

## Quick start

```bash
git clone <your-repo-url> flute
cd flute

# Install Kismet, add your user to kismet + dialout, set capture capabilities
sudo python3 flute.py --setup
# log out and back in if groups were added

# See what the machine has
python3 flute.py --check

# Authorized capture (you will be asked to type YES)
sudo python3 flute.py
```

`--setup` uses `apt`, `dnf`, or `pacman` depending on the distro. On Pop!_OS, Ubuntu, and Debian, Kismet is often **not** in the default repos; setup adds the [official Kismet apt repository](https://www.kismetwireless.net/packages/) (release, then git/nightly if needed), then installs `kismet` plus `iw`, `rfkill`, and `gpsd`.

## What `--setup` and each capture do

Lessons from field use are built in:

| Step                                                        | Why                                                                 |
| ----------------------------------------------------------- | ------------------------------------------------------------------- |
| Install Kismet + `kismet_cap_linux_wifi` / `linuxbluetooth` | Capture helpers                                                     |
| `setcap cap_net_admin,cap_net_raw` on those helpers         | Monitor mode without full root                                      |
| Add the login user to `kismet` and `dialout`                | Helpers + USB GPS (`/dev/ttyUSB0` is typically `root:dialout`)      |
| `rfkill unblock` wifi and bluetooth                         | Soft-blocked radios (common on laptops) look like “no signal”       |
| Remove leftover `kismon*` monitor interfaces                | A previous run can leave a VAP that needs root to delete            |
| Unmanage **only** the chosen Wi-Fi iface in NetworkManager  | Ethernet stays up                                                   |
| Write Kismet’s HTTP password under `$HOME/.kismet/`         | Live status / localhost UI                                          |
| Skip GPS if the serial node is unreadable                   | Don’t hang Kismet; tell you to run `--setup` or sudo                |
| Use **gpsd** when the puck speaks SiRF binary               | GlobalSat BU-353S4 often is not NMEA; Kismet serial cannot parse it |
| Offer to refresh IEEE MAC vendors if missing or >180 days   | Asks first (default no) so air-gapped hosts are not blocked         |
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
3. If `ieee_mac_vendors.csv` is missing or older than 180 days, asks whether to download it (default **no**; needs internet if you say yes).
4. Lists wireless controllers and asks you to pick one (USB monitor-capable adapters are marked recommended).
5. Lists Bluetooth controllers and asks you to pick one (or skip).
6. Autodetects a USB NMEA GPS.
7. Asks for **UserID** (e.g. your username or employee ID), **operator name**, and **test name** (e.g. `Warehouse 4 north wing`).
8. Asks for **channel hop rate** (default `5`).
9. Unmanages the chosen Wi-Fi interface from NetworkManager and starts Kismet.
10. Prints GPS / device counts every 5 seconds. Press **Ctrl-C** to stop, or use `--duration`.
11. Finalizes the `.kismet` log and writes reports, including IEEE `ieee_manufacturer`.

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
| `--download-ieee`                               | Download/refresh `ieee_mac_vendors.csv` without asking (needs internet)  |
| `--no-download-ieee`                            | Do not download the IEEE vendor file (offline / air-gapped)              |
| `--i-have-roe`                                  | Confirm signed ROE / written authorization (required when not a TTY)     |
| `--userid`                                      | Operator user ID (username or employee ID)                               |
| `--operator-name NAME`                          | Operator full name                                                       |
| `--test-name NAME`                              | Test / location name                                                     |
| `--hop-rate N`                                  | Wi-Fi channel hops per second (default `5` = 200 ms/channel; range 1–20) |
| `--wifi IFACE`                                  | Skip the Wi-Fi picker                                                    |
| `--bluetooth hciX`                              | Skip the Bluetooth picker                                                |
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
| `flute_devices.csv`     | Every device (MAC, SSID, `ieee_manufacturer`, signal, frequency, GPS, names) |
| `flute_wifi.csv`        | Wi-Fi subset                                                                    |
| `flute_bluetooth.csv`   | Bluetooth subset                                                                |
| `flute_gps_track.csv`   | Surveyor track (when a fix existed)                                             |
| `*.kismet`              | Native Kismet database                                                          |
| `kismet_server.log`     | Kismet stdout                                                                   |

Do not commit capture output. Indoor GPS can take minutes or fail; the script keeps collecting and leaves coordinates empty until there is a fix.

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
| Hardware rfkill                              | Flip the airplane / wireless kill switch                                              |
| IEEE vendor file missing / stale             | You will be asked before any download (default no). Use `--download-ieee` online, or `--no-download-ieee` offline |

## License

The Magic Flute is free software under the **GNU General Public License v3.0 or later** (GPL-3.0-or-later). See [LICENSE](LICENSE) for the full terms.

You may run, share, and modify it. If you distribute this program or a modified version, you must keep it under the GPL and provide the corresponding source. There is **no warranty**.

Kismet, which this tool launches, is separately licensed by its authors (also GPL). Their terms apply to Kismet itself.

The GPL covers copyright of the software. It does **not** authorize wireless collection. You still need lawful authority (ROE or equivalent) before you run a survey.

## Repository contents

```
flute.py               # setup, checks, Kismet launcher, reports (GPL-3.0-or-later)
ieee_mac_vendors.csv   # IEEE OUI cache (optional download; not in git)
README.md
LICENSE                # GNU GPL v3
.gitignore
```
