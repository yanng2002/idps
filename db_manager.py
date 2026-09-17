#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Gestionnaire d'interactions SQLite
Auteur : Gokeng Passo Yann Vanick
"""

import sqlite3
import hashlib
try:
    # Load pandas dynamically so static analyzers do not require it to be
    # installed in every environment (the database manager can still import).
    from importlib import import_module

    pd = import_module("pandas")
except ImportError:
    pd = None

DB_PATH = '/home/passo/idps_yoli/idps_yoli.db'

def get_connection():
    return sqlite3.connect(DB_PATH)

def verify_user_credentials(username, password):
    """ Vérifie les identifiants d'un utilisateur en base de données """
    try:
        hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT role FROM users WHERE username = ? AND password_hash = ? "
            "AND (status IS NULL OR status = 'ACTIVE')",
            (username, hashed_pwd)
        )
        row = cursor.fetchone()
        conn.close()
        return row[0] if row else None
    except Exception as e:
        print(f"[ERREUR DB] Échec d'authentification : {e}")
        return None

def add_user(username, password, role="Opérateur SOC"):
    """ Ajoute un nouvel utilisateur avec mot de passe haché dans la DB """
    try:
        hashed_pwd = hashlib.sha256(password.encode()).hexdigest()
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", (username, hashed_pwd, role))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERREUR DB] Échec d'ajout d'utilisateur : {e}")
        return False

def get_all_users():
    """ Récupère la liste des utilisateurs enregistrés """
    if pd is None:
        return None
    try:
        conn = get_connection()
        df = pd.read_sql_query(
            "SELECT id, username, role, created_at, status FROM users ORDER BY id ASC",
            conn
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def deactivate_user(username):
    """Desactive un compte sans supprimer son historique."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE users SET status='INACTIVE' WHERE username=?",
            (username,)
        )
        conn.commit()
        changed = cursor.rowcount > 0
        conn.close()
        return changed
    except Exception as e:
        print(f"[ERREUR DB] Échec de désactivation utilisateur : {e}")
        return False

def get_recent_suricata_alerts(limit=2500):
    """Récupère les alertes Suricata persistées, si la table existe."""
    if pd is None:
        return None
    try:
        conn = get_connection()
        df = pd.read_sql_query(
            "SELECT * FROM suricata_alerts ORDER BY id DESC LIMIT ?",
            conn,
            params=(limit,)
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()

def log_suricata_alert(alert):
    """Enregistre une alerte Suricata issue d'un evenement eve.json."""
    try:
        conn = get_connection()
        conn.execute('''
            INSERT INTO suricata_alerts (
                timestamp, flow_id, pcap_cnt, interface, event_type,
                src_ip, src_port, dst_ip, dst_port, protocol, app_protocol,
                action, gid, signature_id, revision, signature, category,
                severity
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            alert.get('timestamp'), alert.get('flow_id'), alert.get('pcap_cnt'),
            alert.get('in_iface'), alert.get('event_type'), alert.get('src_ip'),
            alert.get('src_port'), alert.get('dest_ip'), alert.get('dest_port'),
            alert.get('proto'), alert.get('app_proto'), alert.get('action'),
            alert.get('gid'), alert.get('signature_id'), alert.get('rev'),
            alert.get('signature'), alert.get('category'), alert.get('severity')
        ))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERREUR DB] Échec d'insertion de l'alerte Suricata : {e}")
        return False

def log_flow_event(timestamp, src_ip, dst_ip, dst_port, protocol, bytes_total, pkts_total, anomaly_score, prediction, reason=None):
    """ Enregistre un flux réseau analysé dans la table traffic_logs """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO traffic_logs (timestamp, src_ip, dst_ip, dst_port, protocol, bytes_total, pkts_total, anomaly_score, prediction)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, src_ip, dst_ip, str(dst_port), protocol, bytes_total, pkts_total, anomaly_score, prediction))

        if prediction == 'Anomalie':
            cursor.execute('''
                INSERT INTO anomalies (
                    traffic_log_id, timestamp, src_ip, dst_ip, dst_port,
                    protocol, bytes_total, pkts_total, anomaly_score, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cursor.lastrowid, timestamp, src_ip, dst_ip, str(dst_port),
                protocol, bytes_total, pkts_total, anomaly_score,
                reason or "Anomalie comportementale IA"
            ))

        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERREUR DB] Échec d'insertion du flux : {e}")

def add_mitigation_rule(source_type, source_alert_id, action, target_ip, status="ACTIVE"):
    """Enregistre une decision de mitigation liee a une alerte."""
    try:
        conn = get_connection()
        conn.execute('''
            INSERT INTO mitigation_rules
                (source_type, source_alert_id, action, target_ip, execution_date, status)
            VALUES (?, ?, ?, ?, DATETIME('now'), ?)
        ''', (source_type, source_alert_id, action, target_ip, status))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[ERREUR DB] Échec d'enregistrement de la mitigation : {e}")
        return False

def add_banned_ip(ip, reason="Anomalie comportementale IA"):
    """ Ajoute ou réactive une IP dans la table banned_ips """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO banned_ips (ip_address, banned_at, reason, status)
            VALUES (?, DATETIME('now'), ?, 'ACTIVE')
            ON CONFLICT(ip_address) DO UPDATE SET status='ACTIVE', banned_at=DATETIME('now'), reason=excluded.reason
        ''', (ip, reason))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERREUR DB] Échec d'enregistrement IP bloquée : {e}")

def unban_ip_in_db(ip):
    """ Marque une IP comme libérée dans la base SQLite """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE banned_ips SET status='RELEASED' WHERE ip_address=?", (ip,))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERREUR DB] Échec du déblocage IP : {e}")

def flush_banned_ips_in_db():
    """ Marque toutes les IP comme libérées (lors d'un iptables -F) """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE banned_ips SET status='RELEASED' WHERE status='ACTIVE'")
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[ERREUR DB] Échec du flush des IP : {e}")

def get_active_banned_ips():
    """ Récupère la liste des adresses IP actuellement bloquées """
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT ip_address FROM banned_ips WHERE status='ACTIVE'")
        rows = cursor.fetchall()
        conn.close()
        return [r[0] for r in rows]
    except Exception:
        return []

def get_recent_flows_from_db(limit=2500):
    """ Récupère l'historique des flux enregistrés sous forme de DataFrame """
    if pd is None:
        return None
    try:
        conn = get_connection()
        df = pd.read_sql_query(f"SELECT * FROM traffic_logs ORDER BY id DESC LIMIT {limit}", conn)
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()
