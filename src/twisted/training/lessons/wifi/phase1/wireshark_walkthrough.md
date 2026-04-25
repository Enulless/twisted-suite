---
step_id: wifi.phase1.wireshark_walkthrough
procedure: wifi
stage: phase1
title: Wireshark client probe analysis (walkthrough)
estimated_minutes: 8
---

## What We Are Doing

Open the captured .pcap file in Wireshark and filter for probe request frames to identify client-disclosed SSIDs.

wireshark target_capture-01.cap

Apply display filter:

wlan.fc.type_subtype == 0x04

Why: Client devices broadcast probe requests for every network they have previously connected to. This reveals additional target networks not currently broadcasting and may expose corporate SSIDs or home networks of client employees.
