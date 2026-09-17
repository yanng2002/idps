#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Script d'entraînement du modèle IA
Génère les fichiers isolation_forest_yoli.pkl et scaler_yoli.pkl
"""

import json
import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

EVE_JSON_PATH = '/var/log/suricata/eve.json'
MODEL_PATH = '/opt/yoli_idps/models/isolation_forest_yoli.pkl'
SCALER_PATH = '/opt/yoli_idps/models/scaler_yoli.pkl'

def extract_features_from_eve(filepath):
    data = []
    if not os.path.exists(filepath):
        print(f"[ATTENTION] {filepath} introuvable. Génération de données synthétiques de référence pour le test...")
        # Données de repli (synthétiques) pour initialiser le modèle si eve.json n'a pas encore de flux
        for _ in range(1000):
            bytes_ts = 500
            bytes_tc = 1200
            pkts_ts = 5
            pkts_tc = 6
            age = 10
            total_b = bytes_ts + bytes_tc + 1e-5
            total_p = pkts_ts + pkts_tc + 1e-5
            data.append([bytes_ts, bytes_tc, pkts_ts, pkts_tc, age, bytes_ts / total_b, pkts_ts / total_p])
        return pd.DataFrame(data, columns=['bytes_ts', 'bytes_tc', 'pkts_ts', 'pkts_tc', 'age', 'byte_ratio', 'pkt_ratio'])

    with open(filepath, 'r') as f:
        for line in f:
            try:
                log = json.loads(line)
                if log.get('event_type') == 'flow':
                    flow = log['flow']
                    bytes_ts = flow.get('bytes_toserver', 0)
                    bytes_tc = flow.get('bytes_toclient', 0)
                    pkts_ts = flow.get('pkts_toserver', 0)
                    pkts_tc = flow.get('pkts_toclient', 0)
                    age = flow.get('age', 0)

                    total_b = bytes_ts + bytes_tc + 1e-5
                    total_p = pkts_ts + pkts_tc + 1e-5

                    data.append([
                        bytes_ts, bytes_tc, pkts_ts, pkts_tc, age,
                        bytes_ts / total_b, pkts_ts / total_p
                    ])
            except Exception:
                continue

    if not data:
        print("[INFO] Aucun flux trouvé dans eve.json. Utilisation d'une baseline initiale...")
        return extract_features_from_eve("non_existent_file")

    return pd.DataFrame(data, columns=['bytes_ts', 'bytes_tc', 'pkts_ts', 'pkts_tc', 'age', 'byte_ratio', 'pkt_ratio'])

print("[YOLI-IDPS] Extraction des données d'apprentissage...")
df = extract_features_from_eve(EVE_JSON_PATH)

print("[YOLI-IDPS] Entraînement de Isolation Forest et du StandardScaler...")
scaler = StandardScaler()
scaled_data = scaler.fit_transform(df)

model = IsolationForest(contamination=0.01, random_state=42)
model.fit(scaled_data)

os.makedirs('/opt/yoli_idps/models', exist_ok=True)
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)

print(f"[OK] Modèle sauvegardé sous : {MODEL_PATH}")
print(f"[OK] Scaler sauvegardé sous : {SCALER_PATH}")
