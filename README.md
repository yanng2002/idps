
£ YOLI-IDPS



IDPS hybride : Suricata (signatures) + Isolation Forest (anomalies) + pfSense REST API (prevention).



££ Auteur

GOKENG PASSO Yann Vanick - IAI Cameroun - 2026



££ Composants

- yoli_realtime_monitor.py : moniteur IA temps reel

- train_model.py : entrainement Isolation Forest

- Dashboard_idps.py : dashboard Streamlit

- db_manager.py : gestion SQLite

- feature_utils.py : extraction de features

- pfsense_control_api.py : pont vers pfSense REST API



££ Installation

pip install -r requirements.txt



££ Configuration

Creer un fichier .env avec PFSENSE_API_KEY et PFSENSE_HOST.



££ Lancement

python3 yoli_realtime_monitor.py

streamlit run Dashboard_idps.py

