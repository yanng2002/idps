# YOLI-IDPS — IDPS Hybride assisté par Intelligence Artificielle

Système de détection et de prévention d'intrusion combinant :
- **Suricata** (détection par signatures)
- **Isolation Forest** (détection comportementale / anomalies Zero-Day)
- **pfSense REST API** (prévention automatique)

## 🎓 Contexte

Projet de fin de stage académique — IAI Cameroun (Centre d'Excellence Technologique Paul Biya)
Entreprise d'accueil : **YOLI TECHNOLOGIES** (Buea, Cameroun)
Note : **17,5/20**

## 🏗️ Architecture


[Kali] ──► [pfSense/Suricata] ──► syslog UDP/514 ──► [SOC Ubuntu]
│ │
│ ├─► rsyslog
│ ├─► yoli_realtime_monitor.py (Isolation Forest)
│ ├─► SQLite (logs + alertes)
│ └─► Dashboard_idps.py (Streamlit)
│
└──◄── REST API (BLOCKLIST) ◄───────────┘


## 🧩 Composants

| Fichier | Rôle |
|---|---|
| `yoli_realtime_monitor.py` | Moniteur IA temps réel (Isolation Forest) |
| `train_model.py` | Entraînement du modèle |
| `Dashboard_idps.py` | Dashboard Streamlit (2FA + RBAC) |
| `db_manager.py` | Gestion SQLite |
| `feature_utils.py` | Extraction des features réseau |
| `pfsense_control_api.py` | Pont vers pfSense REST API |

## ⚙️ Installation

```bash
pip install -r requirements.txt

PFSENSE_API_KEY=votre_cle_api
PFSENSE_HOST=http://192.168.40.1

# 1. Entraîner le modèle (première fois)
python3 train_model.py

# 2. Lancer le moniteur IA
python3 yoli_realtime_monitor.py

# 3. Lancer le dashboard
streamlit run Dashboard_idps.py

Fonctionnalités de sécurité
Authentification 2FA (TOTP, RFC 6238)

RBAC : Administrateur SOC / Opérateur SOC

Anti-faux-positifs : seuil de 3 détections en 60s avant blocage

Whitelist dynamique (gateway, DNS, IP locale)

Ports critiques protégés (SSH, Dashboard) — alerte seule

Déduplication des logs Suricata (flow_id + tx_id)

Stack technique
Python • Suricata • pfSense • scikit-learn • Streamlit • SQLite • Plotly • rsyslog • GNS3 • VMware

Licence
MIT


**Commit message** : `Amélioration du README`

---

## 📊 Récapitulatif final

**Après ces uploads**, ton dépôt GitLab contiendra :


idps/
├── Dashboard_idps.py
├── db_manager.py
├── feature_utils.py ← à ajouter
├── init_db.py
├── pfsense_control_api.py ← à ajouter
├── train_model.py
├── yoli_realtime_monitor1.py
├── requirements.txt ← à ajouter
├── README.md ← à améliorer
├── configs/
│ ├── rsyslog.conf ← à ajouter
│ └── 30-pfsense.conf ← à ajouter
└── models/
├── isolation_forest_yoli.pkl ← optionnel
└── scaler_yoli.pkl ← optionnel


 → dans `models/`

**Envoie-moi une capture du dépôt GitLab après**, et on vérifiera que tout est là. 💪

---

## 💡 Bonus : optionnel mais efficace

Si tu veux automatiser tout ça **depuis le SOC**, on peut configurer un `git push` direct via un **mirror** ou un **dépôt local + push manuel**. Mais c'est long à mettre en place, donc pour l'instant, **l'upload manuel via navigateur** est la solution la plus rapide. 🚀