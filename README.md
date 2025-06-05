# 🔍 Domain Reputation Checker

Este proyecto es una herramienta de **análisis de reputación de dominios** que recopila datos de múltiples fuentes de inteligencia de amenazas y los combina para dar una evaluación final de seguridad.

## 🚀 Características

- 🔎 RDAP WHOIS Lookup
- 🛡️ [VirusTotal](https://www.virustotal.com/) Integration
- 🚨 [AbuseIPDB](https://www.abuseipdb.com/) Lookup
- 📷 [URLScan.io](https://urlscan.io/) Analysis
- 🛰️ [AlienVault OTX](https://otx.alienvault.com/) Threat Intelligence
- 📊 Evaluación final (Buena / Sospechosa / Mala)

## 🧰 Requisitos

- Python 3.7+
- Conexión a internet
- Claves de API para:
  - VirusTotal
  - AbuseIPDB
  - URLScan.io
  - AlienVault OTX

## 📦 Instalación

1. Clona este repositorio:

```bash
git clone https://github.com/tuusuario/domain-reputation-checker.git
cd domain-reputation-checker
Instala las dependencias necesarias:
pip install -r requirements.txt
Nota: Si requirements.txt no existe, simplemente instala requests:
pip install requests
Configura tus claves de API editando el script:
VT_API_KEY = "TU_API_KEY_VIRUSTOTAL"
ABUSEIPDB_API_KEY = "TU_API_KEY_ABUSEIPDB"
URLSCAN_API_KEY = "TU_API_KEY_URLSCAN"
OTX_API_KEY = "TU_API_KEY_OTX"

⚙️ Uso
Ejecuta el script con:

python check_domain.py
Introduce el dominio que deseas analizar, por ejemplo:

Introduce el dominio (ej. example.com): evil-domain.xyz
📋 Resultado Esperado

La herramienta imprime:

  Datos de WHOIS (RDAP)
  Detecciones en VirusTotal
  Reportes en AbuseIPDB
  Escaneo y análisis de URLScan.io
  Información de AlienVault OTX
  Evaluación final con emojis:
      ✅ Buena
      ⚠️ Sospechosa
      ❌ Mala
      📁 Estructura del Proyecto

domain-reputation-checker/
├── check_domain.py     # Script principal
├── README.md           # Este archivo
└── requirements.txt    # (Opcional) Lista de dependencias
🛡️ Aviso Legal

Esta herramienta está diseñada solo para fines educativos y de análisis legítimo. No la utilices para escanear dominios sin autorización.
📬 Contacto

¿Sugerencias, problemas o mejoras? Abre un issue o contáctame en david.delgado.deniz@gmail.com
