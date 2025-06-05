import requests
import socket
import time

# API KEYS
VT_API_KEY = "721a964b6804e7f7559925002430d83ca6ea350ca20a536e52172b79291fabe9"
ABUSEIPDB_API_KEY = "6c5cdbb3fd5e2cfe0813136f3d936052f5d1d0f07df1779d2010b62ee5a8053deea279a512b37746"
URLSCAN_API_KEY = "019740d0-4876-731e-8871-47e219837c4b"
OTX_API_KEY = "7374baded2074c18b2692ad170c40eb69e284f65fdba66f33934c5cdcbd6fe6c"

# === RDAP WHOIS ===
def get_rdap_info(domain):
    try:
        url = f"https://rdap.org/domain/{domain}"
        r = requests.get(url)
        if "application/json" not in r.headers.get("Content-Type", ""):
            return {"error": "RDAP no devolvió JSON"}
        data = r.json()
        return {
            "Registrar": data.get("registrar", {}).get("name", "N/A"),
            "Status": data.get("status", []),
            "Nameservers": [ns["ldhName"] for ns in data.get("nameservers", [])],
        }
    except Exception as e:
        return {"error": f"RDAP falló: {str(e)}"}

# === VirusTotal ===
def virustotal_lookup(domain):
    try:
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers)
        if "application/json" not in r.headers.get("Content-Type", ""):
            return {"error": "VirusTotal no devolvió JSON"}
        data = r.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        return {
            "Reputation": data["data"]["attributes"].get("reputation"),
            "Stats": stats,
            "Positives": positives
        }
    except Exception as e:
        return {"error": f"VirusTotal error: {str(e)}"}

# === AbuseIPDB ===
def abuseipdb_lookup(ip):
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": ABUSEIPDB_API_KEY
        }
        params = {"ipAddress": ip, "maxAgeInDays": "90"}
        r = requests.get(url, headers=headers, params=params)
        if "application/json" not in r.headers.get("Content-Type", ""):
            return {"error": "AbuseIPDB no devolvió JSON"}
        data = r.json()["data"]
        return {
            "Abuse Score": data["abuseConfidenceScore"],
            "Country": data["countryCode"],
            "Total Reports": data["totalReports"]
        }
    except Exception as e:
        return {"error": f"AbuseIPDB error: {str(e)}"}

# === URLScan.io ===
def urlscan_lookup(domain):
    try:
        headers = {
            "API-Key": URLSCAN_API_KEY,
            "Content-Type": "application/json"
        }
        payload = {
            "url": f"http://{domain}",
            "visibility": "private"
        }
        submission = requests.post("https://urlscan.io/api/v1/scan/", json=payload, headers=headers)
        if submission.status_code != 200:
            return {"error": f"URLScan error en el envío: {submission.status_code}"}
        result_url = submission.json().get("api")
        time.sleep(10)
        result = requests.get(result_url)
        if "application/json" not in result.headers.get("Content-Type", ""):
            return {"error": "URLScan no devolvió JSON válido"}
        data = result.json()
        verdicts = data.get("verdicts", {}).get("overall", {})
        return {
            "Score": verdicts.get("score", "N/A"),
            "Malicious": verdicts.get("malicious", False),
            "Tags": data.get("page", {}).get("tags", []),
            "Country": data.get("page", {}).get("country", "Desconocido")
        }
    except Exception as e:
        return {"error": f"URLScan falló: {str(e)}"}

# === AlienVault OTX ===
def otx_lookup(domain):
    try:
        headers = {
            "X-OTX-API-KEY": OTX_API_KEY
        }
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"
        r = requests.get(url, headers=headers)
        if "application/json" not in r.headers.get("Content-Type", ""):
            return {"error": "OTX no devolvió JSON"}
        data = r.json()
        pulses = data.get("pulse_info", {}).get("pulses", [])
        return {
            "Malicious": len(pulses) > 0,
            "Pulses": len(pulses),
            "Tags": list(set(tag for p in pulses for tag in p.get("tags", [])))
        }
    except Exception as e:
        return {"error": f"OTX falló: {str(e)}"}

# === Evaluación combinada ===
def evaluar_reputacion(vt, abuse, urlscan, otx):
    puntaje = 0
    if vt.get("Positives", 0) > 5:
        puntaje += 2
    elif vt.get("Positives", 0) > 0:
        puntaje += 1

    if abuse.get("Abuse Score", 0) > 50:
        puntaje += 2
    elif abuse.get("Abuse Score", 0) > 10:
        puntaje += 1

    if urlscan.get("Malicious", False):
        puntaje += 2

    if otx.get("Malicious", False):
        puntaje += 2

    if puntaje <= 1:
        return "✅ Buena"
    elif puntaje <= 3:
        return "⚠️ Sospechosa"
    else:
        return "❌ Mala"

# === Principal ===
def check_domain_reputation(domain):
    print(f"📡 Analizando: {domain}")

    print("\n🔍 WHOIS (RDAP):")
    whois = get_rdap_info(domain)
    for k, v in whois.items():
        print(f"  {k}: {v}")

    print("\n🛡️ VirusTotal:")
    vt = virustotal_lookup(domain)
    for k, v in vt.items():
        print(f"  {k}: {v}")

    try:
        ip = socket.gethostbyname(domain)
        print(f"\n🌐 IP Resuelta: {ip}")
        print("\n🚨 AbuseIPDB:")
        abuse = abuseipdb_lookup(ip)
        for k, v in abuse.items():
            print(f"  {k}: {v}")
    except Exception as e:
        ip = None
        abuse = {"error": f"No se pudo resolver IP: {str(e)}"}
        print(f"  Error al resolver IP: {str(e)}")

    print("\n🔎 URLScan.io:")
    urlscan = urlscan_lookup(domain)
    for k, v in urlscan.items():
        print(f"  {k}: {v}")

    print("\n🛰️ AlienVault OTX:")
    otx = otx_lookup(domain)
    for k, v in otx.items():
        print(f"  {k}: {v}")

    print("\n📊 Evaluación Global:")
    reputacion = evaluar_reputacion(vt, abuse, urlscan, otx)
    print(f"➡️ Reputación general del dominio: {reputacion}")

# === Entrada ===
if __name__ == "__main__":
    dominio = input("Introduce el dominio (ej. example.com): ").strip()
    check_domain_reputation(dominio)
