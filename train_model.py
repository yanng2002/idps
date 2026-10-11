#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Script d'entraînement du modèle d'apprentissage automatise
"""

import os
import random
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib

from feature_utils import FEATURE_COLUMNS, extract_feature_row

# Chemin mis à jour vers le fichier de logs distant de pfSense
TRAFFIC_CSV_PATH = '/var/log/pfsense_remote.log'
MODEL_PATH = '/opt/yoli_idps/models/isolation_forest_yoli.pkl'
SCALER_PATH = '/opt/yoli_idps/models/scaler_yoli.pkl'

# En dessous de ce nombre de flux réels, on considère qu'il n'y a pas
# assez de données pour un modèle fiable et on complète avec du synthétique.
MIN_REAL_SAMPLES = 500


def generate_synthetic_baseline(n=1000):
    """
    Baseline synthétique de secours pour valider le pipeline.
    """
    print("[ATTENTION] Données synthétiques utilisées : ce modèle sert à "
          "tester le pipeline, PAS à détecter des menaces réelles. "
          "Relancez ce script sur un vrai journal avant tout déploiement.")
    profils = [
        (22, (200, 4000), (500, 20000), (5, 60), (5, 80), (5, 600)),
        (8501, (300, 5000), (1000, 50000), (5, 100), (10, 150), (1, 300)),
        (8502, (300, 5000), (1000, 50000), (5, 100), (10, 150), (1, 300)),
        (443, (200, 3000), (500, 15000), (3, 40), (5, 60), (1, 120)),
        (53, (40, 200), (60, 400), (1, 3), (1, 3), (0, 2)),
    ]
    rows = []
    for _ in range(n):
        port, b_ts_r, b_tc_r, p_ts_r, p_tc_r, age_r = random.choice(profils)
        rows.append(extract_feature_row(
            port,
            random.randint(*b_ts_r), random.randint(*b_tc_r),
            random.randint(*p_ts_r), random.randint(*p_tc_r),
            random.randint(*age_r),
        ))
    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)


def extract_features_from_csv(filepath):
    rows = []
    if os.path.exists(filepath):
        try:
            # Lecture du fichier CSV avec gestion d'encodage
            # errors='ignore' permet de contourner les éventuels caractères invalides reçus via syslog
            df_logs = pd.read_csv(filepath, encoding='utf-8', on_bad_lines='skip', engine='python')
            
            # Filtrer sur les événements de type 'flow' si la colonne existe
            if 'event_type' in df_logs.columns:
                df_logs = df_logs[df_logs['event_type'] == 'flow']
            
            # Extraction des caractéristiques pour chaque ligne
            for _, row in df_logs.iterrows():
                try:
                    rows.append(extract_feature_row(
                        int(row.get('dest_port', 0)),
                        int(row.get('bytes_toserver', 0)),
                        int(row.get('bytes_toclient', 0)),
                        int(row.get('pkts_toserver', 0)),
                        int(row.get('pkts_toclient', 0)),
                        int(row.get('age', 0)),
                    ))
                except Exception:
                    continue
        except Exception as e:
            print(f"[!] Erreur de lecture du fichier CSV pfSense : {e}")

    # Mécanisme de fallback si les données réelles sont insuffisantes
    if len(rows) < MIN_REAL_SAMPLES:
        print(f"[INFO] Seulement {len(rows)} flux réels trouvés dans "
              f"{filepath} (minimum recommandé : {MIN_REAL_SAMPLES}).")
        synthetic_df = generate_synthetic_baseline(1000)
        if rows:
            real_df = pd.DataFrame(rows, columns=FEATURE_COLUMNS)
            return pd.concat([real_df, synthetic_df], ignore_index=True)
        return synthetic_df

    return pd.DataFrame(rows, columns=FEATURE_COLUMNS)



print("[YOLI-IDPS] Extraction des données d'apprentissage depuis les logs pfSense...")
df = extract_features_from_csv(TRAFFIC_CSV_PATH)
print(f"[YOLI-IDPS] {len(df)} échantillons prêts pour l'entraînement.")

print("[YOLI-IDPS] Entraînement de l'algorithme Isolation Forest...")
scaler = StandardScaler()
scaled_data = scaler.fit_transform(df)

model = IsolationForest(contamination=0.01, random_state=42)
model.fit(scaled_data)

os.makedirs('/opt/yoli_idps/models', exist_ok=True)
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)

print(f"[OK] Modèle de détection sauvegardé sous : {MODEL_PATH}")
print(f"[OK] Scaler sauvegardé sous : {SCALER_PATH}")
