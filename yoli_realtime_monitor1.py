#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Moteur de Détection IDPS & Actionneur IPS
Auto-Découverte des Infrastructure Critiques & Prévention Proactive
Auteur : Gokeng Passo Yann Vanick
"""

import json
import os
import time
import subprocess
import joblib
import pandas as pd
import numpy as np
import db_manager

# --- 1. CHEMINS DE CONFIGURATION ---
EVE_JSON_PATH = '/var/log/suricata/eve.json'
# Fichier binaire contenant le modele Isolation Forest entraine.
MODEL_PATH = '/opt/yoli_idps/models/isolation_forest_yoli.pkl'
# Fichier binaire contenant le scaler ajuste sur les memes caracteristiques.
SCALER_PATH = '/opt/yoli_idps/models/scaler_yoli.pkl'

# --- 2. AUTO-DÉCOUVERTE DYNAMIQUE DE LA WHITELIST ---
def auto_discover_whitelist():
    """ Détecte automatiquement la passerelle, l'IP de la machine et les adresses critiques """
    # Initialise les adresses locales qui ne doivent jamais etre bloquees.
    whitelist = {
        "127.0.0.1",
        "0.0.0.0",
        "::1"
    }

    try:
        # Recupere les adresses IP configurees sur la machine.
        output_ips = subprocess.check_output("hostname -I", shell=True).decode().split()
        # Ajoute chaque adresse locale a la liste de protection.
        for ip in output_ips:
            whitelist.add(ip)
    except Exception:
        # Continue meme si hostname n'est pas disponible.
        pass

    try:
        # Recupere l'adresse de la passerelle par defaut du reseau.
        cmd_gw = "ip route show default | awk '{print $3}'"
        gateway_ip = subprocess.check_output(cmd_gw, shell=True).decode().strip()
        # Protege la passerelle lorsqu'elle a bien ete trouvee.
        if gateway_ip:
            whitelist.add(gateway_ip)
    except Exception:
        # La decouverte des autres adresses reste independante de cette etape.
        pass

    try:
        # Lit les serveurs DNS locaux afin d'eviter leur blocage accidentel.
        with open('/etc/resolv.conf', 'r') as f:
            # Analyse chaque ligne de configuration DNS.
            for line in f:
                # Seules les lignes nameserver contiennent une IP utile.
                if line.startswith('nameserver'):
                    # Recupere la deuxieme colonne, qui contient l'adresse DNS.
                    dns_ip = line.split()[1]
                    whitelist.add(dns_ip)
    except Exception:
        # Le fichier peut ne pas exister dans certains environnements.
        pass

    try:
        # Determine le sous-reseau associe a une route locale.
        cmd_host = "ip route | grep src | awk '{print $1}' | head -n 1"
        subnet = subprocess.check_output(cmd_host, shell=True).decode().strip()
        # Ajoute des adresses usuelles du sous-reseau comme protection.
        if '/' in subnet:
            net_prefix = subnet.rsplit('.', 1)[0]
            whitelist.add(f"{net_prefix}.1")
            whitelist.add(f"{net_prefix}.2")
            whitelist.add(f"{net_prefix}.254")
    except Exception:
        # Une route incomplete ne doit pas arreter le moteur.
        pass

    # Retourne l'ensemble sans doublons utilise par block_ip().
    return whitelist

# Construit la whitelist une seule fois au demarrage du moteur.
WHITELIST_IPS = auto_discover_whitelist()
# Conserve en memoire les IP deja bloquees pendant cette execution.
BANNED_IPS = set()
# References vers les objets charges depuis les fichiers du modele.
model = None
scaler = None
# Permet de detecter le remplacement du fichier modele sur disque.
last_model_mtime = 0

# --- 3. CHARGEMENT & RECHARGE DYNAMIQUE DU MODÈLE IA ---
def load_model_and_scaler():
    # Indique que la fonction met a jour les variables globales du moteur.
    global model, scaler, last_model_mtime
    # Ne tente un chargement que si les deux artefacts existent.
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        try:
            # Lit la date de modification du modele pour eviter les rechargements inutiles.
            current_mtime = os.path.getmtime(MODEL_PATH)
            # Recharge uniquement apres une premiere execution ou une modification.
            if current_mtime != last_model_mtime:
                # Deserialise le modele entraine.
                model = joblib.load(MODEL_PATH)
                # Deserialise le scaler ajuste pendant l'entrainement.
                scaler = joblib.load(SCALER_PATH)
                # Memorise la version actuellement chargee.
                last_model_mtime = current_mtime
                print("[YOLI-IDPS] Moteur IA & Scaler chargés avec succès.")
        except Exception as e:
            # Conserve l'ancien modele si le nouveau fichier est illisible.
            print(f"[ERREUR] Échec du chargement du modèle : {e}")

def check_and_reload_model():
    # Ignore la verification si aucun fichier modele n'est present.
    if os.path.exists(MODEL_PATH):
        # Compare la version sur disque avec celle deja chargee.
        if os.path.getmtime(MODEL_PATH) != last_model_mtime:
            print("[YOLI-IDPS] Nouveaux poids détectés ! Rechargement du modèle...")
            load_model_and_scaler()

# --- 4. ACTIONNEUR DE SÉCURITÉ (IPTABLES & SQLITE) ---
def block_ip(ip_address, reason="Anomalie comportementale détectée"):
    # Ignore une adresse vide ou deja traitee pour eviter les doublons IPTables.
    if not ip_address or ip_address in BANNED_IPS:
        return

    # Ne bloque jamais une adresse necessaire au fonctionnement de l'infrastructure.
    if ip_address in WHITELIST_IPS:
        print(f"[PROTECTION SYSTEME] Blocage ignoré pour l'IP critique : {ip_address}")
        return

    # Ignore certaines adresses IPv6 locales ou multicast non bloquables utilement.
    if ip_address.startswith("fe80:") or ip_address.startswith("ff02:"):
        return

    # Construit la regle qui refuse les paquets entrants depuis cette adresse.
    try:
        # Passe les arguments separement pour eviter qu'une valeur issue du
        # journal eve.json puisse etre interpretee comme une commande shell.
        subprocess.run(
            ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"],
            check=True
        )
        # Memorise l'adresse pour ne pas ajouter deux fois la meme regle.
        BANNED_IPS.add(ip_address)
        # Conserve le blocage dans la base afin que le dashboard puisse l'afficher.
        db_manager.add_banned_ip(ip_address, reason=reason)
        # Enregistre egalement la decision de mitigation dans son historique.
        db_manager.add_mitigation_rule("IsolationForest", None, "DROP", ip_address)
        print(f"[PREVENTION PROACTIVE YOLI] IP Malveillante bloquée via iptables : {ip_address}")
    except Exception as e:
        print(f"[ERREUR] Échec du blocage de {ip_address} : {e}")

# --- 5. ANALYSE ET PRÉDICTION IA ---
def process_flow_event(data):
    # Traite uniquement un evenement flow deja decode depuis eve.json.
    try:
        # Extrait les informations d'adressage et de protocole du flux.
        src_ip = data.get('src_ip')
        dst_ip = data.get('dest_ip', 'N/A')
        dst_port = data.get('dest_port', 'N/A')
        protocol = data.get('proto', 'N/A')
        timestamp = data.get('timestamp', '')
        # Recupere le sous-objet Suricata contenant les compteurs du flux.
        flow = data.get('flow', {})

        bytes_ts = flow.get('bytes_toserver', 0)
        bytes_tc = flow.get('bytes_toclient', 0)
        pkts_ts = flow.get('pkts_toserver', 0)
        pkts_tc = flow.get('pkts_toclient', 0)
        age = flow.get('age', 0)

        # Additionne les octets envoyes dans les deux directions.
        total_bytes = bytes_ts + bytes_tc
        # Calcule la part des octets envoyes vers le serveur.
        byte_ratio = bytes_ts / total_bytes if total_bytes > 0 else 0.0

        # Additionne les paquets envoyes dans les deux directions.
        total_pkts = pkts_ts + pkts_tc
        # Calcule la part des paquets envoyes vers le serveur.
        pkt_ratio = pkts_ts / total_pkts if total_pkts > 0 else 0.0

        # Respecte exactement l'ordre des sept caracteristiques utilise a l'entrainement.
        feature_names = ['bytes_toserver', 'bytes_toclient', 'pkts_toserver', 'pkts_toclient', 'age', 'byte_ratio', 'pkt_ratio']
        # Construit une ligne pandas compatible avec StandardScaler et IsolationForest.
        features = pd.DataFrame([[bytes_ts, bytes_tc, pkts_ts, pkts_tc, age, byte_ratio, pkt_ratio]], columns=feature_names)

        # Initialise un score lisible meme lorsque le modele n'est pas disponible.
        anomaly_score = 0.0
        # Signale l'absence du modele au lieu de classer abusivement le flux
        # comme normal lorsqu'aucune prediction IA n'est possible.
        prediction_str = "Modèle indisponible"
        # Aucune justification n'est necessaire tant qu'aucune anomalie n'est detectee.
        reason = None

        # Verifie explicitement que les deux composants IA sont charges.
        if model is not None and scaler is not None:
            # Normalise les valeurs avec les parametres appris sur les donnees d'entrainement.
            scaled_features = scaler.transform(features)
            # Produit la decision Isolation Forest : 1 normal, -1 anomalie.
            prediction = model.predict(scaled_features)
            # Convertit la decision_function en score ou une valeur elevee indique
            # un comportement plus eloigne de la normale.
            decision_score = float(model.decision_function(scaled_features)[0])
            anomaly_score = float(np.clip(0.5 - decision_score, 0.0, 1.0))
            # Le modele ayant repondu, le flux peut maintenant recevoir une
            # classification normale ou anormale.
            prediction_str = "Normal"

            # Une decision -1 declenche le traitement de securite.
            if prediction[0] == -1:
                prediction_str = "Anomalie"
                if total_pkts > 1500:
                    reason = "Densité élevée de paquets (Possible attaque Syn Flood)"
                elif total_bytes > 100000:
                    reason = "Volume de charge utile hors-norme (Possible exfiltration)"
                else:
                    reason = "Anomalie comportementale détectée par Isolation Forest"

                print(f"[DÉTECTION IA YOLI] Anomalie détectée depuis l'IP : {src_ip}")
                block_ip(src_ip, reason=reason)

            # Lorsque le modele manque, le flux est conserve avec un score nul,
            # plutot que d'inventer une prediction heuristique dans le moteur.

            # Enregistre chaque flux et sa decision dans traffic_logs.
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
        # Affiche l'erreur pour faciliter le diagnostic sans arreter la boucle.
        print(f"[ERREUR] Échec du traitement du flux : {e}")

def process_suricata_alert(data):
    # Persiste une alerte fondee sur une signature Suricata dans la table dediee.
    try:
        # Recupere les details de la signature imbriques dans l'evenement.
        alert = data.get('alert', {})
        # Construit un objet plat correspondant aux colonnes de suricata_alerts.
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
        # Envoie l'alerte normalisee au gestionnaire SQLite.
        db_manager.log_suricata_alert(alert_record)
    except Exception as e:
        # Ignore une alerte mal formee mais conserve le fonctionnement du moteur.
        print(f"[ERREUR] Échec de l'enregistrement Suricata : {e}")

# --- 6. ÉCOUTE TEMPS RÉEL DU FLUX RÉSEAU ---
def realtime_stream_listener():
    # Attend la creation du journal avant d'ouvrir le flux de lecture.
    print(f"[YOLI-IDPS] Écoute active du flux réseau dans {EVE_JSON_PATH}...")

    # Suricata doit etre demarre avant que le moteur puisse recevoir des evenements.
    while not os.path.exists(EVE_JSON_PATH):
        print(f"[ATTENTION] Attente de la création de {EVE_JSON_PATH} par Suricata...")
        time.sleep(2)

    # Ouvre le journal en lecture seule afin de suivre les nouvelles lignes.
    with open(EVE_JSON_PATH, 'r') as f:
        # Se positionne a la fin pour traiter uniquement les nouveaux evenements.
        f.seek(0, os.SEEK_END)

        while True:
            # Verifie a chaque tour si un nouveau modele doit etre charge.
            check_and_reload_model()
            # Lit la prochaine ligne produite par Suricata.
            line = f.readline()
            # En l'absence de nouvelle ligne, attend sans monopoliser le processeur.
            if not line:
                time.sleep(0.1)
                continue

            try:
                # Transforme la ligne JSON en evenement exploitable.
                data = json.loads(line)
                # Les flux vont vers Isolation Forest et traffic_logs.
                if data.get('event_type') == 'flow':
                    process_flow_event(data)
                # Les alertes de signatures vont vers suricata_alerts.
                elif data.get('event_type') == 'alert':
                    process_suricata_alert(data)
            except json.JSONDecodeError:
                # Ignore une ligne partiellement ecrite par Suricata et poursuit la lecture.
                continue

if __name__ == '__main__':
    # Affiche les adresses protegees afin de rendre la configuration observable.
    print(f"[YOLI-IDPS] Initialisation de la Whitelist Dynamique : {WHITELIST_IPS}")
    # Signale le demarrage du composant de detection comportementale.
    print("[YOLI-IDPS] Chargement du moteur d'Intelligence Artificielle...")
    # Charge le modele et le scaler avant de traiter le premier flux.
    load_model_and_scaler()

    # Reinitialise les anciennes regles INPUT au demarrage du service.
    # Utilise une liste d'arguments afin d'eviter l'interpretation shell.
    subprocess.run(["iptables", "-F", "INPUT"])
    # Aligne le statut SQLite sur la remise a zero d'IPTables.
    db_manager.flush_banned_ips_in_db()
    print("[YOLI-IDPS] Tables iptables et base de données réinitialisées.")

    try:
        # Lance la boucle de surveillance jusqu'a un arret clavier.
        realtime_stream_listener()
    except KeyboardInterrupt:
        # Termine proprement le service lorsque l'operateur appuie sur Ctrl+C.
        print("\n[YOLI-IDPS] Arrêt propre du service de surveillance.")
