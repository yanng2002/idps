#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Extraction de features partagée (entraînement + inférence)
"""
# Ports considérés comme du trafic d'administration/infrastructure.
MANAGEMENT_PORTS = {22, 23, 3389}
WEB_DASHBOARD_PORTS = {8501, 8501}
DNS_PORTS = {53}
MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
DATABASE_PORTS = {3306, 5432, 1433, 27017, 6379}
 
# Ports que le moteur IPS ne bloque JAMAIS automatiquement : on alerte,
# on ne coupe pas l'accès qui sert justement à administrer (SSH) ou à
# surveiller (dashboard) le système. Un blocage automatique sur ces ports
# créerait un risque d'auto-verrouillage.
CRITICAL_PORTS_NO_AUTOBLOCK = {22, 8501, 8502}
 
FEATURE_COLUMNS = [
    'bytes_toserver', 'bytes_toclient', 'pkts_toserver', 'pkts_toclient', 'age',
    'byte_ratio', 'pkt_ratio',
    'is_management', 'is_web_dashboard', 'is_dns', 'is_mail', 'is_database', 'is_other',
]
 
 
def get_port_category(port):
    """Classe un port de destination dans une catégorie de service connue."""
    try:
        port = int(port)
    except (TypeError, ValueError):
        return 'other'
    if port in MANAGEMENT_PORTS:
        return 'management'
    if port in WEB_DASHBOARD_PORTS:
        return 'web_dashboard'
    if port in DNS_PORTS:
        return 'dns'
    if port in MAIL_PORTS:
        return 'mail'
    if port in DATABASE_PORTS:
        return 'database'
    return 'other'
 
 
def extract_feature_row(dest_port, bytes_ts, bytes_tc, pkts_ts, pkts_tc, age):
    """
    Construit une ligne de features dans l'ordre exact de FEATURE_COLUMNS.
    Utilisée à la fois à l'entraînement (sur eve.json historique) et en
    temps réel.
    """
    total_b = bytes_ts + bytes_tc + 1e-5
    total_p = pkts_ts + pkts_tc + 1e-5
    byte_ratio = bytes_ts / total_b
    pkt_ratio = pkts_ts / total_p
 
    category = get_port_category(dest_port)
    one_hot = {
        'is_management': 1 if category == 'management' else 0,
        'is_web_dashboard': 1 if category == 'web_dashboard' else 0,
        'is_dns': 1 if category == 'dns' else 0,
        'is_mail': 1 if category == 'mail' else 0,
        'is_database': 1 if category == 'database' else 0,
        'is_other': 1 if category == 'other' else 0,
    }
 
    row = [bytes_ts, bytes_tc, pkts_ts, pkts_tc, age, byte_ratio, pkt_ratio]
    row += [one_hot[c] for c in FEATURE_COLUMNS[7:]]
    return row
