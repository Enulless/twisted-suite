---
step_id: wifi.phase1.monitor_mode
procedure: wifi
stage: phase1
title: Enable monitor mode (airmon-ng)
estimated_minutes: 8
---

## What We Are Doing

Kill interfering processes and enable monitor mode on the wireless adapter.

airmon-ng check kill

airmon-ng start wlan0

After execution, the interface is renamed (typically wlan0mon). Verify with:

iwconfig wlan0mon

Why: Monitor mode allows the adapter to receive all 802.11 frames regardless of destination MAC address. The 'check kill' command stops NetworkManager and wpa_supplicant, which would otherwise fight the adapter for control.
