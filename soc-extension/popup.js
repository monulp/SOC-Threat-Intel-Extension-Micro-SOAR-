let currentIoc = "";
let currentType = "";

function defang(ioc) {
    if (!ioc) return "N/A";
    return ioc.replace(/http/gi, 'hxxp').replace(/\./g, '[.]');
}

function isPrivateIP(ip) {
    return /^(10\.|192\.168\.|127\.|172\.(1[6-9]|2[0-9]|3[0-1])\.)/.test(ip);
}

function updateStatus(msg) {
    document.getElementById('status-msg').innerText = msg;
}

chrome.storage.local.get(['searchTarget'], (res) => {
    if (res.searchTarget) {
        document.getElementById('ioc-input').value = res.searchTarget;
        chrome.storage.local.remove('searchTarget'); 
        runAnalysis(res.searchTarget);
    }
});

document.getElementById('search-btn').addEventListener('click', () => {
    const ioc = document.getElementById('ioc-input').value.trim();
    if (ioc) runAnalysis(ioc);
});

async function runAnalysis(ioc) {
    currentIoc = ioc;
    const ipRegex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
    const hashRegex = /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/;

    if (hashRegex.test(ioc)) currentType = "hash";
    else if (ipRegex.test(ioc)) currentType = "ip";
    else if (ioc.toLowerCase().startsWith("http")) currentType = "url";
    else currentType = "domain";

    if (currentType === "ip" && isPrivateIP(ioc)) {
        updateStatus(`[OPSEC] ${ioc} is an internal IP. Query blocked.`);
        return;
    }

    updateStatus(`Querying intelligence for ${currentType}...`);
    
    document.getElementById('vt-card').style.display = 'block';
    document.getElementById('shodan-card').style.display = (currentType === "ip") ? 'block' : 'none';
    document.getElementById('abuse-card').style.display = (currentType === "ip") ? 'block' : 'none';
    document.getElementById('pivot-links').style.display = 'flex';

    document.getElementById('vt-extra-1').innerHTML = '';
    document.getElementById('vt-extra-2').innerHTML = '';
    document.getElementById('vt-extra-3').innerHTML = '';

    chrome.storage.local.get(['vtKey', 'abuseKey', 'shodanKey'], async (keys) => {
        if (!keys.vtKey || (currentType === "ip" && (!keys.abuseKey || !keys.shodanKey))) {
            updateStatus("Missing API Keys in Options!");
        }

        // 1. VirusTotal Fetch
        let vtUrl = "";
        if (currentType === "hash") vtUrl = `https://www.virustotal.com/api/v3/files/${ioc.toLowerCase()}`;
        else if (currentType === "ip") vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ioc}`;
        else if (currentType === "domain") vtUrl = `https://www.virustotal.com/api/v3/domains/${ioc}`;
        else if (currentType === "url") vtUrl = `https://www.virustotal.com/api/v3/urls/${btoa(ioc).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')}`;

        try {
            let vtRes = await fetch(vtUrl, { headers: { "x-apikey": keys.vtKey }});
            if (vtRes.ok) {
                let attr = (await vtRes.json()).data.attributes;
                let stats = attr.last_analysis_stats;
                let total = stats.malicious + stats.undetected + stats.harmless + stats.suspicious;
                
                let scoreEl = document.getElementById('vt-score');
                scoreEl.innerText = `${stats.malicious} / ${total} (Rep: ${attr.reputation || 0})`;
                scoreEl.className = stats.malicious > 0 ? "val alert" : "val clean";

                if (currentType === "hash") {
                    document.getElementById('vt-extra-1').innerHTML = `<span class="label">Type:</span> <span class="val">${attr.type_description || "-"}</span>`;
                    document.getElementById('vt-extra-2').innerHTML = `<span class="label">Name:</span> <span class="val">${attr.meaningful_name || "-"}</span>`;
                    document.getElementById('vt-extra-3').innerHTML = `<span class="label">Threat:</span> <span class="val">${attr.popular_threat_classification?.suggested_threat_label || "None"}</span>`;
                } else if (currentType === "ip") {
                    document.getElementById('vt-extra-1').innerHTML = `<span class="label">Country:</span> <span class="val">${attr.country || "-"}</span>`;
                    document.getElementById('vt-extra-2').innerHTML = `<span class="label">ASN Owner:</span> <span class="val">${attr.as_owner || "-"}</span>`;
                }
            } else { document.getElementById('vt-score').innerText = "Not found in VT"; }
        } catch (e) { document.getElementById('vt-score').innerText = "Error"; }

        // 2. Shodan Fetch (IP Only)
        if (currentType === "ip" && keys.shodanKey) {
            try {
                let shoRes = await fetch(`https://api.shodan.io/shodan/host/${ioc}?key=${keys.shodanKey}`);
                if (shoRes.ok) {
                    let shoData = await shoRes.json();
                    document.getElementById('sho-org').innerText = shoData.org || shoData.isp || "Unknown";
                    document.getElementById('sho-ports').innerText = shoData.ports ? shoData.ports.join(", ") : "None";
                    
                    let vulns = shoData.vulns ? Object.keys(shoData.vulns) : [];
                    let vulnEl = document.getElementById('sho-vulns');
                    vulnEl.innerText = vulns.length > 0 ? vulns.join(", ") : "None detected";
                    vulnEl.className = vulns.length > 0 ? "val alert" : "val clean";
                } else {
                    document.getElementById('sho-org').innerText = "Not in Shodan DB";
                }
            } catch (e) { document.getElementById('sho-org').innerText = "Fetch Error"; }
        }

        // 3. AbuseIPDB Fetch (IP Only)
        if (currentType === "ip" && keys.abuseKey) {
            try {
                let abRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ioc}&maxAgeInDays=90`, { headers: { "Key": keys.abuseKey, "Accept": "application/json" }});
                if (abRes.ok) {
                    let data = (await abRes.json()).data;
                    let abScoreEl = document.getElementById('ab-score');
                    abScoreEl.innerText = `${data.abuseConfidenceScore}%`;
                    abScoreEl.className = data.abuseConfidenceScore > 0 ? "val alert" : "val clean";
                    document.getElementById('ab-reports').innerText = data.totalReports;
                    document.getElementById('ab-isp').innerText = data.isp;
                    document.getElementById('ab-tor').innerText = data.isTor ? "YES" : "No";
                }
            } catch (e) { document.getElementById('ab-score').innerText = "Error"; }
        }
        updateStatus(`Analysis complete for ${defang(ioc)}`);
    });
}

// Pivot Buttons Logic
document.getElementById('pivot-vt').addEventListener('click', () => {
    if (!currentIoc) return;
    let url = "https://www.virustotal.com/gui/search/" + encodeURIComponent(currentIoc);
    if (currentType === "ip") url = `https://www.virustotal.com/gui/ip-address/${currentIoc}`;
    else if (currentType === "domain") url = `https://www.virustotal.com/gui/domain/${currentIoc}`;
    else if (currentType === "hash") url = `https://www.virustotal.com/gui/file/${currentIoc}`;
    chrome.tabs.create({ url: url });
});
document.getElementById('pivot-ab').addEventListener('click', () => {
    if (currentType === "ip") chrome.tabs.create({ url: `https://www.abuseipdb.com/check/${currentIoc}`});
});
document.getElementById('pivot-sh').addEventListener('click', () => {
    if (currentType === "ip") chrome.tabs.create({ url: `https://www.shodan.io/host/${currentIoc}`});
});
document.getElementById('pivot-us').addEventListener('click', () => {
    let q = (currentType === "ip") ? `ip:"${currentIoc}"` : `domain:"${currentIoc}"`;
    chrome.tabs.create({ url: `https://urlscan.io/search/#${encodeURIComponent(q)}`});
});

// Copy to Clipboard (Defanged & Formatted)
document.getElementById('copy-btn').addEventListener('click', () => {
    if (!currentIoc) return;
    const safeIoc = defang(currentIoc);
    let report = `=== THREAT INTEL TRIAGE ===\nIndicator: ${safeIoc}\n\n[VirusTotal]\nDetection: ${document.getElementById('vt-score').innerText}\n`;
    
    if (document.getElementById('vt-extra-1').innerText) report += `${document.getElementById('vt-extra-1').innerText.replace(/\n/g, ' ')}\n`;
    if (document.getElementById('vt-extra-2').innerText) report += `${document.getElementById('vt-extra-2').innerText.replace(/\n/g, ' ')}\n`;
    if (document.getElementById('vt-extra-3').innerText) report += `${document.getElementById('vt-extra-3').innerText.replace(/\n/g, ' ')}\n`;

    if (currentType === "ip") {
        report += `\n[Shodan]\nOrg: ${document.getElementById('sho-org').innerText}\nPorts: ${document.getElementById('sho-ports').innerText}\nVulns: ${document.getElementById('sho-vulns').innerText}\n`;
        report += `\n[AbuseIPDB]\nConfidence: ${document.getElementById('ab-score').innerText}\nReports: ${document.getElementById('ab-reports').innerText}\nISP: ${document.getElementById('ab-isp').innerText}\nTor: ${document.getElementById('ab-tor').innerText}\n`;
    }
    report += `===========================`;

    navigator.clipboard.writeText(report).then(() => {
        let btn = document.getElementById('copy-btn');
        btn.innerText = "✅ Copied!";
        btn.style.background = "#28a745";
        setTimeout(() => { btn.innerText = "📋 Copy Report (Defanged)"; btn.style.background = "#0e639c"; }, 2000);
    });
});
