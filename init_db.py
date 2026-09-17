#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Security Operations Center (SOC)
Module : Initialisation de la base de données
Auteur : Gokeng Passo Yann Vanick
"""

import sqlite3
import os
import hashlib

DB_PATH = "/home/passo/idps_yoli/idps_yoli.db"

def add_column_if_missing(cursor, table_name, column_name, column_definition):
    """Ajoute une colonne sans modifier une base deja initialisee."""
    columns = {row[1] for row in cursor.execute(f"PRAGMA table_info({table_name})")}
    if column_name not in columns:
        cursor.execute(
            f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_definition}"
        )

def init_database():
    """Crée les tables de la base de données SQLite si elles n'existent pas."""

    db_dir = os.path.dirname(DB_PATH)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Table du trafic réseau global
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT,
            bytes_total INTEGER,
            pkts_total INTEGER,
            anomaly_score REAL,
            prediction TEXT
        );
    """)

    # Table dédiée aux anomalies identifiées
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            traffic_log_id INTEGER,
            timestamp TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT,
            app_protocol TEXT,
            action TEXT,
            severity INTEGER,
            bytes_total INTEGER,
            pkts_total INTEGER,
            anomaly_score REAL,
            reason TEXT,
            status TEXT DEFAULT 'NEW',
            FOREIGN KEY (traffic_log_id) REFERENCES traffic_logs(id)
        );
    """)

    # Alertes Suricata fondees sur les signatures et les regles.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS suricata_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            flow_id INTEGER,
            pcap_cnt INTEGER,
            interface TEXT,
            event_type TEXT,
            src_ip TEXT NOT NULL,
            src_port INTEGER,
            dst_ip TEXT NOT NULL,
            dst_port INTEGER,
            protocol TEXT,
            app_protocol TEXT,
            action TEXT,
            gid INTEGER,
            signature_id INTEGER,
            revision INTEGER,
            signature TEXT,
            category TEXT,
            severity INTEGER,
            status TEXT DEFAULT 'NEW'
        );
    """)

    # Decisions de mitigation produites par Suricata ou par le moteur IA.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS mitigation_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source_type TEXT NOT NULL,
            source_alert_id INTEGER,
            action TEXT NOT NULL,
            target_ip TEXT NOT NULL,
            execution_date TEXT NOT NULL,
            status TEXT DEFAULT 'ACTIVE'
        );
    """)

    # Table des adresses IP neutralisées (bloquées via iptables)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS banned_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT UNIQUE NOT NULL,
            banned_at TEXT NOT NULL,
            reason TEXT,
            status TEXT DEFAULT 'ACTIVE'
        );
    """)

    # Table de gestion des utilisateurs
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'ACTIVE'
        );
    """)

    # Migration des bases creees avec une version precedente du projet.
    for column_name, column_definition in (
        ("traffic_log_id", "INTEGER"),
        ("src_port", "INTEGER"),
        ("app_protocol", "TEXT"),
        ("action", "TEXT"),
        ("severity", "INTEGER"),
        ("status", "TEXT DEFAULT 'NEW'"),
    ):
        add_column_if_missing(cursor, "anomalies", column_name, column_definition)
    add_column_if_missing(cursor, "users", "status", "TEXT DEFAULT 'ACTIVE'")

    # Insertion d'un utilisateur administrateur par défaut si la table est vide
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        default_admin = "admin"
        default_password_hash = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("""
            INSERT INTO users (username, password_hash, role)
            VALUES (?, ?, ?)
        """, (default_admin, default_password_hash, "Administrateur SOC"))
        print("[+] Compte 'admin' initialisé avec le mot de passe 'admin123'")

    conn.commit()
    conn.close()
    print(f"[+] Base de données initialisée avec succès : {DB_PATH}")

if __name__ == "__main__":
    init_database()
