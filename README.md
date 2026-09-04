# 🛡️ SOC Threat Intel Extension (Micro-SOAR)

A lightweight, zero-click Manifest V3 browser extension designed to eliminate Tier 1 and Tier 2 SOC alert triage toil. 

This tool acts as a micro-SOAR (Security Orchestration, Automation, and Response) utility living directly in your browser. It auto-detects observables (IPs, Domains, URLs, Hashes), routes them to the appropriate Threat Intelligence APIs, and formats the output for safe pasting into enterprise ticketing systems like Microsoft Sentinel, Jira, or ServiceNow.

![Extension Demo](./demo.png) *(Note: Replace with an actual screenshot of your popup UI)*

## 🚀 The Operational Problem
During incident triage, analysts spend 3 to 5 minutes per alert manually copying indicators, opening multiple tabs (VirusTotal, AbuseIPDB, Shodan), parsing the results, and manually "defanging" the indicators (e.g., converting `http://` to `hxxp://`) so they don't accidentally execute in a work ticket. Multiply this by 30 alerts a shift, and hours are lost to pure administrative friction.

**The Solution:** This extension reduces that 5-minute workflow to exactly **2 seconds** without ever leaving the SIEM dashboard.

## 🛠️ Core Features

*   **Intelligent Auto-Detection:** Automatically identifies whether the highlighted text is an IPv4 address, Domain, URL, or File Hash (MD5, SHA1, SHA256) and routes it to the correct API endpoints.
*   **Multi-Source Enrichment:**
    *   **VirusTotal (v3):** Pulls malicious detection ratios, reputation, file names, and threat classifications.
    *   **AbuseIPDB (v2):** Pulls abuse confidence scores, ISP data, and Tor exit node status.
    *   **Shodan:** Pulls infrastructure context, open ports, and known CVE vulnerabilities for IPs.
*   **Strict OPSEC Controls:** Includes a native regex filter that immediately blocks internal, private, and loopback IPs (RFC 1918) from being routed to external public APIs.
*   **Ticket-Safe Clipboard Export:** A one-click "Copy Report" button that formats the raw JSON telemetry into a clean, readable text block while automatically **defanging** the indicator (e.g., `1[.]1[.]1[.]1` or `hxxps://malware[.]com`).
*   **One-Click Pivot Links:** Dynamically generates deep-links to the web portals of VT, Shodan, AbuseIPDB, and URLScan if a deeper manual investigation is required.

## 🏗️ Architecture & Tech Stack
*   **Framework:** Manifest V3 (Compatible with Chrome, Edge, Brave, and Firefox)
*   **Language:** Vanilla JavaScript (ES6+), HTML5, CSS3 (No external libraries or heavy dependencies)
*   **Security:** API keys are stored strictly in local browser storage (`chrome.storage.local`) and are never synced or transmitted elsewhere. Adheres to strict Content Security Policies (CSP).

## ⚙️ Installation (Developer Mode)

Because this is a custom internal tool, it is installed as an "Unpacked Extension."

1. Clone or download this repository to your local machine.
2. Open your Chromium-based browser (Chrome, Edge, Brave) and navigate to the extensions page:
   * Chrome: `chrome://extensions/`
   * Edge: `edge://extensions/`
3. Toggle **Developer mode** ON (usually in the top right corner).
4. Click **Load unpacked** and select the folder containing the extension files.
5. Click the Extension icon in your toolbar, go to **Options**, and securely paste your API keys for VirusTotal, AbuseIPDB, and Shodan.

## 🕹️ Usage Guide

There are two ways to use the tool:

1. **The Right-Click Context Menu:** Highlight any IP, Domain, URL, or Hash inside your SIEM, EDR, or log viewer. Right-click the text and select **"Deep Triage for..."** The UI will pop open instantly with the enriched data.
2. **The Manual Popup:** Click the extension icon in your browser toolbar to open the search dashboard. Paste an indicator into the search bar and click **Analyze**.

Once the data populates, click **📋 Copy Report (Defanged)** to push the sanitized summary directly to your system clipboard.

---
*Built for fast, secure, and accurate threat hunting.*
