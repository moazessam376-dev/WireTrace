# WireTrace

Single-file, offline PCAP and router event-log analyzer for support engineers who don't have Wireshark.

## Why it exists

Support staff at a large ISP needed to triage home-broadband captures without installing Wireshark. Captures must never leave the machine.

## Privacy

WireTrace runs entirely in the browser. It does not upload files or make network calls, except for the optional Google Fonts stylesheet included by the page. This was verified by grepping `index.html` for `fetch(`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`: the actual result was **0 matches**.

## What it decodes

Ethernet, Linux SLL, 802.1Q, IPv4/IPv6, TCP, UDP, DNS, DHCP, ICMP, ARP, and PPPoE, plus hex dumps, follow-TCP-stream views, endpoint summaries, and protocol statistics.

## Findings and heuristics

The analyzer flags likely Wi-Fi flapping, roaming, Ethernet link flaps, PPPoE instability, ARP spoofing, and rogue DHCP activity.

## Event log CSV contract

Event logs use the header `Date,Time,Details,Category,Severity`. Each row contains the date, time, message details, category, and severity. Details are intended to follow stock hostapd, dnsmasq, and kernel syslog formats.

## Usage

Open `index.html` in a browser and drag in files from `samples/`, such as `sample-events.csv` and `sample-capture.pcap`. No server is required.

The sample capture and its generator are synthetic and safe for demonstrations. The generator uses only Python's standard-library `struct` module.
