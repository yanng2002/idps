#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import json
import os
import time
import subprocess
import joblib
import pandas as pd
import numpy as np
from collections import defaultdict, deque, OrderedDict

import db_manager
import pfsense_control_api as p

from feature_utils import FEATURE_COLUMNS, extract_feature_row, CRITICAL_PORTS_NO_AUTOBLOCK

# CHEMINS DE CONFIGURATION 
EVE_JSON_PATH = '/var/log/pfsense_remote.log'
MODEL_PATH = '/opt/yoli_idps/models/isolation_forest_yoli.pkl'
SCALER_PATH = '/opt/yoli_idps/models/scaler_yoli.pkl'

#  CONFIGURATION ANTI-FAUX-POSITIFS
# Nombre de détections anormales rapprochées nécessaires avant le blocage.
ANOMALY_STRIKE_THRESHOLD = 3
# Fenêtre glissante (secondes) sur laquelle ces détections sont comptées.
ANOMALY_WINDOW_SECONDS = 60


# --- 2. AUTO-DÉCOUVERTE DYNAMIQUE DE LA WHITELIST ---
def auto_discover_whitelist():
    """ Détecte automatiquement la passerelle, l'IP de la machine et les adresses critiques """
    whitelist = {"127.0.0.1", "0.0.0.0", "::1"}

    try:
        output_ips = subprocess.check_output("hostname -I", shell=True).decode().split()
        for ip in output_ips:
            whitelist.add(ip)
    except Exception:
        pass

    try:
        cmd_gw = "ip route show default | awk '{print $3}'"
        gateway_ip = subprocess.check_output(cmd_gw, shell=True).decode().strip()
        if gateway_ip:
            whitelist.add(gateway_ip)
    except Exception:
        pass

    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                if line.startswith('nameserver'):
                    dns_ip = line.split()[1]
                    whitelist.add(dns_ip)
    except Exception:
        pass

    try:
        cmd_host = "ip route | grep src | awk '{print $1}' | head -n 1"
        subnet = subprocess.check_output(cmd_host, shell=True).decode().strip()
        if '/' in subnet:
            net_prefix = subnet.rsplit('.', 1)[0]
            whitelist.add(f"{net_prefix}.1")
            whitelist.add(f"{net_prefix}.2")
            whitelist.add(f"{net_prefix}.254")
    except Exception:
        pass

    # Mise à jour de la liste blanche
    whitelist.update({"10.10.1.2", "192.168.30.1", "192.168.40.1"})

    return whitelist


WHITELIST_IPS = auto_discover_whitelist()
BANNED_IPS = set()
anomaly_timestamps = defaultdict(deque)
model = None
scaler = None
last_model_mtime = 0


# =========================================================================
# CACHE DE DÉDUPLICATION
# Évite de traiter plusieurs fois le même événement Suricata.
# Utilise un OrderedDict comme cache LRU (Least Recently Used).
# =========================================================================
_seen_events = OrderedDict()
_MAX_CACHE_SIZE = 10000  # Nombre max d'événements gardés en mémoire


def is_duplicate_event(data):
   
    flow_id = data.get('flow_id')
    if flow_id is None:
        return False  # Pas d'ID, on ne peut pas dédupliquer

    tx_id = data.get('tx_id')
    if tx_id is not None:
        key = f"{flow_id}:{tx_id}"
    else:
        key = str(flow_id)

    if key in _seen_events:
        return True  # Déjà vu

    # Nouveau : on l'ajoute au cache
    _seen_events[key] = time.time()

    # Limite de taille (LRU) : on supprime les plus anciens
    while len(_seen_events) > _MAX_CACHE_SIZE:
        _seen_events.popitem(last=False)

    return False


# --- 3. CHARGEMENT & RECHARGE DYNAMIQUE DU MODÈLE IA ---
def load_model_and_scaler():
    global model, scaler, last_model_mtime
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        current_mtime = os.path.getmtime(MODEL_PATH)
        if current_mtime != last_model_mtime:
            try:
                model = joblib.load(MODEL_PATH)
                scaler = joblib.load(SCALER_PATH)
                print("[YOLI-IDPS] Moteur IA & Scaler chargés avec succès.")
            except Exception as e:
                print(f"[ERREUR] Échec du chargement du modèle : {e}")
            finally:
                last_model_mtime = current_mtime


def check_and_reload_model():
    """Vérifie si le fichier modèle a été mis à jour et recharge si nécessaire.
    N'affiche un message que si le fichier a réellement changé."""
    if not os.path.exists(MODEL_PATH):
        return
    try:
        current_mtime = os.path.getmtime(MODEL_PATH)
    except OSError:
        return
    if current_mtime != last_model_mtime:
        print("[YOLI-IDPS] Nouveaux poids détectés ! Rechargement du modèle...")
        load_model_and_scaler()


# --- 4. ACTIONNEUR DE SÉCURITÉ (PFSENSE + IPTABLES LOCAL + SQLITE) ---
def block_ip(ip_address, reason="Anomalie comportementale détectée"):
    if not ip_address or ip_address in BANNED_IPS:
        return
    if ip_address in WHITELIST_IPS:
        print(f"[PROTECTION SYSTEME] Blocage ignoré pour l'IP critique : {ip_address}")
        return
    if ip_address.startswith("fe80:") or ip_address.startswith("ff02:"):
        return

    pfsense_ok = p.block_ip_on_pfsense(ip_address)

    # Durcissement local du SOC lui-même
    try:
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
    except Exception as e:
        print(f"[ERREUR] Blocage local iptables échoué pour {ip_address} : {e}")

    BANNED_IPS.add(ip_address)
    db_manager.add_banned_ip(ip_address, reason=reason)
    db_manager.add_mitigation_rule(
        "IsolationForest", None,
        "DROP_PFSENSE" if pfsense_ok else "DROP_LOCAL_ONLY",
        ip_address
    )

    if pfsense_ok:
        print(f"[PREVENTION PROACTIVE YOLI] IP bloquée sur pfSense (WAN) + localement : {ip_address}")
    else:
        print(f"[PREVENTION PARTIELLE] Échec du blocage pfSense pour {ip_address}  "
              f"seul le blocage local (inefficace pour protéger le reste du réseau) a été appliqué. "
              f"Vérifiez la connexion SSH vers pfSense (pfsense_control.test_connection()).")


def register_anomaly_and_maybe_block(ip_address, dst_port, reason):
    """
    Comptabilise une détection anormale pour cette IP dans la fenêtre
    glissante, et ne déclenche le blocage que si plusieurs détections s'y
    sont produites. Un flux isolé (souvent un faux positif) ne suffit plus
    à couper l'accès. Chaque détection, même sans blocage, est tracée dans
    mitigation_rules pour garder un historique complet.
    """
    now = time.time()
    history = anomaly_timestamps[ip_address]
    history.append(now)
    while history and now - history[0] > ANOMALY_WINDOW_SECONDS:
        history.popleft()

    if len(history) < ANOMALY_STRIKE_THRESHOLD:
        print(f"[SURVEILLANCE YOLI] Anomalie {len(history)}/{ANOMALY_STRIKE_THRESHOLD} "
              f"pour {ip_address} (port {dst_port})  pas encore de blocage.")
        db_manager.add_mitigation_rule("IsolationForest", None, "SURVEILLANCE", ip_address, status="INFO")
        return

    block_ip(ip_address, reason=reason)


# --- 5. ANALYSE ET PRÉDICTION IA ---
def process_flow_event(data):
    # === DÉDUPLICATION ===
    if is_duplicate_event(data):
        return  # Événement déjà traité, on ignore silencieusement
    # === FIN DÉDUPLICATION ===

    try:
        src_ip = data.get('src_ip')
        dst_ip = data.get('dest_ip', 'N/A')
        dst_port = data.get('dest_port', 'N/A')
        protocol = data.get('proto', 'N/A')
        timestamp = data.get('timestamp', '')
        flow = data.get('flow', {})

        bytes_ts = flow.get('bytes_toserver', 0)
        bytes_tc = flow.get('bytes_toclient', 0)
        pkts_ts = flow.get('pkts_toserver', 0)
        pkts_tc = flow.get('pkts_toclient', 0)
        age = flow.get('age', 0)

        total_bytes = bytes_ts + bytes_tc
        total_pkts = pkts_ts + pkts_tc

        # Construit la ligne de features EN INCLUANT la catégorie de port
        # (feature_utils.extract_feature_row), dans le même ordre exact
        # qu'à l'entrainement (train_model.py utilise le même module).
        row = extract_feature_row(dst_port, bytes_ts, bytes_tc, pkts_ts, pkts_tc, age)
        features = pd.DataFrame([row], columns=FEATURE_COLUMNS)

        anomaly_score = 0.0
        prediction_str = "Modèle indisponible"
        reason = None

        if model is not None and scaler is not None:
            scaled_features = scaler.transform(features)
            prediction = model.predict(scaled_features)
            decision_score = float(model.decision_function(scaled_features)[0])
            anomaly_score = float(np.clip(0.5 - decision_score, 0.0, 1.0))
            prediction_str = "Normal"

            if prediction[0] == -1:
                prediction_str = "Anomalie"
                if total_pkts > 1500:
                    reason = "Densité élevée de paquets (Possible attaque Syn Flood)"
                elif total_bytes > 100000:
                    reason = "Volume de charge utile hors-norme (Possible exfiltration)"
                else:
                    reason = "Anomalie comportementale détectée par Isolation Forest"

                if dst_port in CRITICAL_PORTS_NO_AUTOBLOCK:
                    reason = f"Alerte (port protégé {dst_port}) : {reason}"
                    print(f"[ALERTE YOLI - PORT CRITIQUE] Comportement inhabituel sur "
                          f"le port {dst_port} depuis {src_ip}  alerte tracée, "
                          f"AUCUN blocage automatique.")
                    db_manager.add_mitigation_rule("IsolationForest", None, "ALERT_ONLY", src_ip, status="INFO")
                else:
                    print(f"[DÉTECTION IA YOLI] Anomalie détectée depuis l'IP : {src_ip} (port {dst_port})")
                    register_anomaly_and_maybe_block(src_ip, dst_port, reason)

        db_manager.log_flow_event(
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            bytes_total=total_bytes,
            pkts_total=total_pkts,
            anomaly_score=anomaly_score,
            prediction=prediction_str,
            reason=reason
        )

    except Exception as e:
        print(f"[ERREUR] Échec du traitement du flux : {e}")


def process_suricata_alert(data):
    # === DÉDUPLICATION ===
    if is_duplicate_event(data):
        return
    # === FIN DÉDUPLICATION ===

    try:
        alert = data.get('alert', {})
        alert_record = {
            'timestamp': data.get('timestamp'),
            'flow_id': data.get('flow_id'),
            'pcap_cnt': data.get('pcap_cnt'),
            'in_iface': data.get('in_iface'),
            'event_type': data.get('event_type'),
            'src_ip': data.get('src_ip'),
            'src_port': data.get('src_port'),
            'dest_ip': data.get('dest_ip'),
            'dest_port': data.get('dest_port'),
            'proto': data.get('proto'),
            'app_proto': data.get('app_proto'),
            'action': alert.get('action'),
            'gid': alert.get('gid'),
            'signature_id': alert.get('signature_id'),
            'rev': alert.get('rev'),
            'signature': alert.get('signature'),
            'category': alert.get('category'),
            'severity': alert.get('severity')
        }
        db_manager.log_suricata_alert(alert_record)
    except Exception as e:
        print(f"[ERREUR] Échec de l'enregistrement Suricata : {e}")


# --- 6. ÉCOUTE TEMPS RÉEL DU FLUX RÉSEAU ---
def parse_json_line(line):
    """
    Isole l'objet JSON dans la ligne, qu'elle soit du JSON pur (une ligne
    = un évènement eve.json) ou préfixée d'un en-tête syslog standard
    ("<134>Sep 26 12:00:00 pfSense suricata: {...}"). Fonctionne dans les
    deux cas sans configuration préalable : on cherche la première
    accolade ouvrante et on ignore tout ce qui la précède.
    """
    idx = line.find('{')
    if idx == -1:
        return None
    try:
        return json.loads(line[idx:])
    except json.JSONDecodeError:
        return None


def realtime_stream_listener():
    print(f"[YOLI-IDPS] Écoute active du flux réseau dans {EVE_JSON_PATH}...")

    while not os.path.exists(EVE_JSON_PATH):
        print(f"[ATTENTION] Attente de la création de {EVE_JSON_PATH} (rsyslog / pfSense)...")
        time.sleep(2)

    with open(EVE_JSON_PATH, 'r') as f:
        f.seek(0, os.SEEK_END)

        while True:
            check_and_reload_model()
            line = f.readline()
            if not line:
                time.sleep(0.1)
                continue

            data = parse_json_line(line)
            if data is None:
                continue

            if data.get('event_type') == 'flow':
                process_flow_event(data)
            elif data.get('event_type') == 'alert':
                process_suricata_alert(data)


if __name__ == '__main__':
    print(f"[YOLI-IDPS] Initialisation de la Whitelist Dynamique : {WHITELIST_IPS}")
    print(f"[YOLI-IDPS] Ports critiques protégés du blocage automatique : {CRITICAL_PORTS_NO_AUTOBLOCK}")
    print("[YOLI-IDPS] Chargement du moteur d'Intelligence Artificielle...")
    load_model_and_scaler()

    print("[YOLI-IDPS] Vérification de la connexion vers pfSense (blocage distant)...")
    if not p.test_connection():
        print("[YOLI-IDPS][ATTENTION] pfSense injoignable en SSH  la prévention se limitera "
              "au blocage local (inefficace pour le reste du réseau) tant que ce n'est pas corrigé.")

    subprocess.run(["iptables", "-F", "INPUT"])
    db_manager.flush_banned_ips_in_db()
    p.flush_pfsense_blocklist()
    print("[YOLI-IDPS] Tables iptables, BLOCKLIST pfSense et base de données réinitialisées.")

    try:
        realtime_stream_listener()
    except KeyboardInterrupt:
        print("\n[YOLI-IDPS] Arrêt propre du service de surveillance.")
