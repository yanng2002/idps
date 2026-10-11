#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Dashboard IDPS/IPS Moderne & Sécurisé
Auteur : Gokeng Passo Yann Vanick
"""

import streamlit as st
import json
import os
import subprocess
import pandas as pd
import numpy as np
import time
import hashlib
import hmac
import struct
import base64
import ipaddress
import plotly.express as px

import db_manager
import pfsense_control_api

EVE_JSON_PATH = '/var/log/pfsense_remote.log'
ISSUER = "YOLI-IDPS"

# --- CONFIGURATION DE LA PAGE STREAMLIT ---
st.set_page_config(
    page_title="YOLI-IDPS | Security Center",
    page_icon="https://img.icons8.com/color/48/shield.png",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- STYLE CSS PERSONNALISÉ (Design moderne avec FontAwesome) ---
st.markdown("""
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    .main { background-color: #0e1117; }
    .stMetric {
        background-color: #1e222d;
        padding: 15px;
        border-radius: 10px;
        border-left: 4px solid #00f2c3;
    }
    div[data-testid="stSidebarUserContent"] { padding-top: 1rem; }
    h1, h2, h3 { color: #f1f5f9; }
    .stTabs [data-baseweb="tab-panel"] {
        padding-top: 1.5rem;
    }
    .icon-green { color: #10b981; margin-right: 8px; }
    .icon-cyan { color: #00f2c3; margin-right: 8px; }
    .icon-red { color: #ef4444; margin-right: 8px; }
    .icon-blue { color: #3b82f6; margin-right: 8px; }
    .icon-orange { color: #f59e0b; margin-right: 8px; }
    .icon-header { vertical-align: middle; margin-right: 10px; }
    .role-badge {
        background-color: #1e293b;
        color: #00f2c3;
        padding: 4px 8px;
        border-radius: 4px;
        font-size: 0.85rem;
    }
    .attack-card {
        background-color: #1e1b2e;
        border: 1px solid #ef4444;
        border-radius: 8px;
        padding: 15px;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# --- GESTION SCHÉMA TOTP EN BASE DE DONNÉES ---
def ensure_otp_schema():
    try:
        conn = db_manager.get_connection()
        cur = conn.cursor()
        cols = {row[1] for row in cur.execute("PRAGMA table_info(users)")}
        if "otp_secret" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN otp_secret TEXT")
        if "otp_confirmed" not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN otp_confirmed INTEGER DEFAULT 0")
        conn.commit()
        conn.close()
    except Exception:
        pass

ensure_otp_schema()

def get_otp_state(username):
    try:
        conn = db_manager.get_connection()
        cur = conn.cursor()
        cur.execute("SELECT otp_secret, otp_confirmed FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None, False
        return row[0], bool(row[1])
    except Exception:
        return None, False

def set_otp_secret(username, secret):
    try:
        conn = db_manager.get_connection()
        conn.execute("UPDATE users SET otp_secret=? WHERE username=?", (secret, username))
        conn.commit()
        conn.close()
    except Exception:
        pass

def confirm_otp(username):
    try:
        conn = db_manager.get_connection()
        conn.execute("UPDATE users SET otp_confirmed=1 WHERE username=?", (username,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def reactivate_user(username):
    try:
        conn = db_manager.get_connection()
        cur = conn.cursor()
        cur.execute("UPDATE users SET status='ACTIVE' WHERE username=?", (username,))
        conn.commit()
        changed = cur.rowcount > 0
        conn.close()
        return changed
    except Exception:
        return False

def new_otp_secret():
    import secrets
    return base64.b32encode(secrets.token_bytes(10)).decode("ascii").rstrip("=")

def generate_totp(secret_b32, digits=6, period=30, for_time=None):
    try:
        padding = (-len(secret_b32)) % 8
        key = base64.b32decode(secret_b32.upper() + "=" * padding)
        if for_time is None:
            for_time = int(time.time())
        counter = int(for_time // period)
        msg = struct.pack(">Q", counter)
        h = hmac.new(key, msg, hashlib.sha1).digest()
        offset = h[-1] & 0x0F
        code_int = (struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return str(code_int).zfill(digits)
    except Exception:
        return "000000"

def verify_totp(secret_b32, code, period=30, window=1):
    code = (code or "").strip()
    if not code:
        return False
    now = int(time.time())
    for i in range(-window, window + 1):
        if generate_totp(secret_b32, for_time=now + i * period) == code:
            return True
    return False

def otpauth_uri(username, secret_b32):
    return f"otpauth://totp/{ISSUER}:{username}?secret={secret_b32}&issuer={ISSUER}&digits=6&period=30"

# --- SESSION ÉTAT ---
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "otp_ok" not in st.session_state:
    st.session_state["otp_ok"] = False
if "user" not in st.session_state:
    st.session_state["user"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

def logout():
    st.session_state["authenticated"] = False
    st.session_state["otp_ok"] = False
    st.session_state["user"] = None
    st.session_state["role"] = None
    st.rerun()

# --- ÉCRAN DE CONNEXION ---
def login_form():
    _, col2, _ = st.columns([1, 1, 1])
    with col2:
        st.markdown("<h2 style='text-align: center; color: #00f2c3;'><i class='fa-solid fa-shield-halved icon-header'></i>YOLI IDPS</h2>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center; color: #94a3b8;'>Portail de Sécurité et Supervision IA</p>", unsafe_allow_html=True)
        st.divider()

        with st.form("login_form"):
            username = st.text_input("Nom d'utilisateur")
            password = st.text_input("Mot de passe", type="password")
            submit_button = st.form_submit_button("Se connecter", use_container_width=True)

            if submit_button:
                role = db_manager.verify_user_credentials(username, password)
                if role:
                    secret, _ = get_otp_state(username)
                    if not secret:
                        secret = new_otp_secret()
                        set_otp_secret(username, secret)
                    st.session_state["authenticated"] = True
                    st.session_state["otp_ok"] = False
                    st.session_state["user"] = username
                    st.session_state["role"] = role
                    st.rerun()
                else:
                    st.error("Identifiants incorrects ou compte inactif.")

# --- ÉCRAN DE VÉRIFICATION TOTP (DOUBLE AUTHENTIFICATION) ---
def otp_form():
    username = st.session_state["user"]
    secret, confirmed = get_otp_state(username)
    _, col2, _ = st.columns([1, 1, 1])
    with col2:
        st.markdown("<h3 style='text-align: center; color: #00f2c3;'><i class='fa-solid fa-lock icon-header'></i>Double Authentification (2FA)</h3>", unsafe_allow_html=True)
        if confirmed:
            st.markdown("<p style='text-align: center; color: #94a3b8;'>Entrez le code à 6 chiffres de votre application d'authentification.</p>", unsafe_allow_html=True)
        else:
            st.warning("Première connexion : associez ce compte à une application (Google Authenticator, Authy...). Clé secrète :")
            st.code(secret)
            st.caption(f"URI technique : {otpauth_uri(username, secret)}")
            st.write("Saisissez le code généré pour confirmer l'activation.")

        with st.form("otp_form"):
            code = st.text_input("Code de validation à 6 chiffres", max_chars=6)
            submit = st.form_submit_button("Valider le code", use_container_width=True)
            if submit:
                if secret and verify_totp(secret, code):
                    if not confirmed:
                        confirm_otp(username)
                    st.session_state["otp_ok"] = True
                    st.rerun()
                else:
                    st.error("Code d'authentification invalide.")

        if st.button("Annuler et se déconnecter", use_container_width=True):
            logout()

# --- GARDE D'ACCÈS ---
if not st.session_state["authenticated"]:
    login_form()
    st.stop()

if not st.session_state["otp_ok"]:
    otp_form()
    st.stop()

# --- FONCTIONS SYSTÈME & DONNÉES ---
def check_service_status(service_name):
    """Vérifie qu'un service systemd est actif (utilisé pour d'autres services éventuels)."""
    try:
        res = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        return res.stdout.strip() == "active"
    except Exception:
        return False

def check_process_running(process_name):
    """Vérifie qu'un processus tourne (ex: yoli_realtime_monitor.py)."""
    try:
        res = subprocess.run(["pgrep", "-f", process_name], capture_output=True, text=True)
        return len(res.stdout.strip()) > 0
    except Exception:
        return False

def check_pfsense_connection():
    """Vérifie que l'API pfSense répond."""
    try:
        return pfsense_control_api.test_connection()
    except Exception:
        return False

def check_suricata_logs():
    """
    Vérifie que les logs Suricata (EVE JSON) arrivent bien au SOC.
    On considère que Suricata est "actif" si le fichier a été modifié
    dans les 5 dernières minutes.
    """
    if not os.path.exists(EVE_JSON_PATH):
        return False
    try:
        mtime = os.path.getmtime(EVE_JSON_PATH)
        return (time.time() - mtime) < 300  # 5 minutes
    except Exception:
        return False

def analyze_anomaly_context(anomalies_df):
    if anomalies_df.empty:
        return None
    top_ip = anomalies_df['src_ip'].value_counts().index[0] if not anomalies_df['src_ip'].empty else "N/A"
    top_port = anomalies_df['dst_port'].value_counts().index[0] if not anomalies_df['dst_port'].empty else "N/A"
    avg_pkts = anomalies_df['pkts_total'].mean()
    avg_bytes = anomalies_df['bytes_total'].mean()

    if avg_pkts > 3000 and avg_bytes < 50000:
        attack_type = "Attaque Volumétrique / DDoS (Syn Flood)"
        desc = "Nombre élevé de paquets transmis avec une faible charge."
    elif avg_bytes > 200000:
        attack_type = "Exfiltration Massive de Données"
        desc = "Volume d'octets transférés anormalement élevé."
    else:
        attack_type = "Scan de Ports / Bruteforce"
        desc = "Tentatives répétées de connexions ciblées."

    return {
        "top_ip": top_ip,
        "top_port": top_port,
        "attack_type": attack_type,
        "description": desc,
        "count": len(anomalies_df)
    }

# --- CHARGEMENT DES DONNÉES DEPUIS LA DB ---
try:
    df_flows = db_manager.get_recent_flows_from_db(limit=300)
    banned_ips = db_manager.get_active_banned_ips() or []
except Exception as e:
    st.error(f"Erreur de connexion à la base de données : {e}")
    df_flows = pd.DataFrame()
    banned_ips = []

if df_flows is None:
    df_flows = pd.DataFrame()

pfsense_ok = check_pfsense_connection()
suricata_ok = check_suricata_logs()
ai_monitor_active = check_process_running("yoli_realtime_monitor.py")

# --- SIDEBAR ---
with st.sidebar:
    st.markdown(f"<i class='fa-solid fa-user icon-blue'></i> **{st.session_state['user']}**", unsafe_allow_html=True)
    st.markdown(f"<span class='role-badge'>{st.session_state['role']}</span>", unsafe_allow_html=True)
    st.write("")

    if st.button("Déconnexion", use_container_width=True):
        logout()

    st.divider()
    st.markdown("### <i class='fa-solid fa-sliders icon-cyan'></i> État du Moteur", unsafe_allow_html=True)

    if suricata_ok:
        st.markdown("<i class='fa-solid fa-circle-check icon-green'></i> **Suricata (pfSense)** : Flux récents", unsafe_allow_html=True)
    else:
        st.markdown("<i class='fa-solid fa-circle-xmark icon-red'></i> **Suricata (pfSense)** : Aucun flux récent", unsafe_allow_html=True)

    if pfsense_ok:
        st.markdown("<i class='fa-solid fa-circle-check icon-green'></i> **API pfSense** : Connectée", unsafe_allow_html=True)
    else:
        st.markdown("<i class='fa-solid fa-circle-xmark icon-red'></i> **API pfSense** : Injoignable", unsafe_allow_html=True)

    if ai_monitor_active:
        st.markdown("<i class='fa-solid fa-circle-check icon-green'></i> **Isolation Forest** : Opérationnel", unsafe_allow_html=True)
    else:
        st.markdown("<i class='fa-solid fa-circle-xmark icon-red'></i> **Isolation Forest** : Inactif", unsafe_allow_html=True)

    st.markdown("<i class='fa-solid fa-shield-cat icon-green'></i> **Pilote IPTables** : Actif", unsafe_allow_html=True)

    st.divider()
    auto_refresh = st.checkbox("Activer l'auto-rafraîchissement", value=False)
    refresh_interval = st.slider("Intervalle (secondes)", 5, 60, 10)

    st.markdown("### <i class='fa-solid fa-bars icon-cyan'></i> Navigation", unsafe_allow_html=True)
    menu_options = ["Vue d'ensemble", "Flux Réseau et IA", "Alertes Suricata", "Gestion des Pare-feu"]
    if st.session_state["role"] == "Administrateur SOC":
        menu_options.append("Administration")
    menu = st.radio("Aller à", menu_options)

# --- HEADER PRINCIPAL ---
st.markdown("<h1><i class='fa-solid fa-shield-virus icon-cyan'></i> YOLI IDPS  Moniteur SOC en temps réel</h1>", unsafe_allow_html=True)
st.caption("Détection d'anomalies comportementales par Isolation Forest et Protection Proactive IPTables / pfSense")

# --- KPI MÉTRIQUES ---
anomalies_df = df_flows[df_flows['prediction'] == 'Anomalie'] if not df_flows.empty and 'prediction' in df_flows.columns else pd.DataFrame()
nb_anomalies = len(anomalies_df)

m1, m2, m3 = st.columns(3)
with m1:
    st.metric("Flux Totaux Analysés", len(df_flows))
with m2:
    st.metric("Anomalies Détectées (IA)", nb_anomalies, delta=f"{nb_anomalies} suspects", delta_color="inverse")
with m3:
    st.metric("IP Bloquées (Sécurité)", len(banned_ips))

st.divider()

# ==========================================
# VUE 1 : VUE D'ENSEMBLE
# ==========================================
if menu == "Vue d'ensemble":
    if not anomalies_df.empty:
        context = analyze_anomaly_context(anomalies_df)
        st.markdown(f"""
        <div class="attack-card">
            <h4 style="color: #ef4444; margin: 0;"><i class="fa-solid fa-triangle-exclamation icon-red"></i> Diagnostic Dynamique de l'Attaque</h4>
            <p style="color: #cbd5e1; margin-top: 8px; margin-bottom: 0;">
                <b>Nature suspectée :</b> {context['attack_type']} ({context['description']})<br>
                <b>IP Attaquante principale :</b> <code style="color: #00f2c3;">{context['top_ip']}</code> |
                <b>Port Cible le plus visé :</b> <code style="color: #00f2c3;">{context['top_port']}</code> |
                <b>Flux suspects actifs :</b> {context['count']}
            </p>
        </div>
        """, unsafe_allow_html=True)

    col_chart, col_table = st.columns([2, 1])

    with col_chart:
        st.markdown("### <i class='fa-solid fa-chart-line icon-cyan'></i> Activité Trafic (Octets / Temps)", unsafe_allow_html=True)
        if not df_flows.empty and "timestamp" in df_flows.columns and "bytes_total" in df_flows.columns:
            fig = px.line(
                df_flows,
                x="timestamp",
                y="bytes_total",
                color="prediction" if "prediction" in df_flows.columns else None,
                color_discrete_map={'Normal': '#00f2c3', 'Anomalie': '#ef4444'},
                markers=True
            )
            fig.update_layout(
                template="plotly_dark",
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                margin=dict(l=20, r=20, t=30, b=20)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("En attente de flux réseau pour afficher le graphique...")

    with col_table:
        st.markdown("### <i class='fa-solid fa-ban icon-red'></i> IP Bloquées Actives", unsafe_allow_html=True)
        if banned_ips:
            df_banned = pd.DataFrame({'IP Cible': banned_ips, 'Action': 'DROP', 'Statut': 'BLOCKED'})
            st.dataframe(df_banned, hide_index=True, use_container_width=True)
        else:
            st.success("Aucune adresse IP bloquée.")

    st.markdown("### <i class='fa-solid fa-user-ninja icon-red'></i> Registre Explicatif des Flux Anormaux (IA)", unsafe_allow_html=True)
    if not anomalies_df.empty:
        st.dataframe(
            anomalies_df[['timestamp', 'src_ip', 'dst_ip', 'dst_port', 'protocol', 'pkts_total', 'bytes_total', 'anomaly_score']].sort_values(by='anomaly_score', ascending=False),
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("Aucune anomalie à afficher.")

# ==========================================
# VUE 2 : FLUX RÉSEAU ET IA
# ==========================================
elif menu == "Flux Réseau et IA":
    st.markdown("### <i class='fa-solid fa-brain icon-cyan'></i> Analyse Comportementale des Flux (Isolation Forest)", unsafe_allow_html=True)
    if not df_flows.empty:
        st.dataframe(df_flows, use_container_width=True)

        if "anomaly_score" in df_flows.columns:
            st.markdown("### <i class='fa-solid fa-chart-bar icon-cyan'></i> Distribution des Scores d'Anomalie", unsafe_allow_html=True)
            fig_hist = px.histogram(
                df_flows, x="anomaly_score",
                color="prediction" if "prediction" in df_flows.columns else None,
                nbins=20, template="plotly_dark",
                color_discrete_map={"Normal": "#10b981", "Anomalie": "#ef4444"}
            )
            st.plotly_chart(fig_hist, use_container_width=True)
    else:
        st.warning("Aucun flux enregistré dans la base de données.")

# ==========================================
# VUE 3 : ALERTES SURICATA
# ==========================================
elif menu == "Alertes Suricata":
    st.markdown("### <i class='fa-solid fa-triangle-exclamation icon-orange'></i> Journaux d'Alertes IDS (Suricata / pfSense)", unsafe_allow_html=True)
    try:
        alerts_df = db_manager.get_recent_suricata_alerts(limit=50)
    except Exception:
        alerts_df = pd.DataFrame()

    if alerts_df is not None and not alerts_df.empty:
        st.dataframe(alerts_df, use_container_width=True)
    else:
        st.info("Aucune alerte Suricata critique enregistrée pour l'instant.")

# ==========================================
# VUE 4 : GESTION DES PARE-FEU
# ==========================================
elif menu == "Gestion des Pare-feu":
    st.markdown("### <i class='fa-solid fa-shield-halved icon-blue'></i> Gestion des IP Bannies et Neutralisation", unsafe_allow_html=True)
    col_a, col_b = st.columns(2)

    with col_a:
        st.markdown("#### Liste des IP Actuellement Bloquées")
        if banned_ips:
            st.write(banned_ips)
            if st.session_state["role"] == "Administrateur SOC":
                ip_to_unban = st.selectbox("Sélectionner une IP à débloquer", options=banned_ips)
                if st.button("Débloquer cette IP", use_container_width=True):
                    # Validation de l'adresse IP avant toute commande
                    try:
                        ipaddress.ip_address(ip_to_unban)
                        subprocess.run(
                            ["iptables", "-D", "INPUT", "-s", ip_to_unban, "-j", "DROP"],
                            check=True
                        )
                    except ValueError:
                        st.error("Adresse IP invalide.")
                    except Exception:
                        pass
                    db_manager.unban_ip_in_db(ip_to_unban)
                    try:
                        pfsense_control_api.unblock_ip_on_pfsense(ip_to_unban)
                    except Exception:
                        pass
                    st.success(f"IP {ip_to_unban} débloquée avec succès.")
                    time.sleep(1)
                    st.rerun()
        else:
            st.success("Aucune adresse IP bloquée activement.")

    with col_b:
        st.markdown("#### Action Manuelle de Sécurité")
        ip_to_ban = st.text_input("Adresse IP à bannir manuellement :")
        if st.button("Bloquer l'IP", use_container_width=True):
            if ip_to_ban:
                try:
                    ipaddress.ip_address(ip_to_ban)  # Validation
                    ok = pfsense_control_api.block_ip_on_pfsense(ip_to_ban)
                    subprocess.run(
                        ["iptables", "-A", "INPUT", "-s", ip_to_ban, "-j", "DROP"],
                        check=True
                    )
                    db_manager.add_banned_ip(ip_to_ban, reason="Blocage manuel opérateur")
                    if ok:
                        st.success(f"L'adresse IP {ip_to_ban} a été bloquée (pfSense + local).")
                    else:
                        st.warning(f"IP {ip_to_ban} bloquée localement (échec API pfSense).")
                    time.sleep(1)
                    st.rerun()
                except ValueError:
                    st.error("Adresse IP invalide.")
                except Exception as e:
                    st.error(f"Échec du blocage : {e}")
            else:
                st.warning("Veuillez entrer une adresse IP valide.")

    st.markdown("---")
    if st.session_state["role"] == "Administrateur SOC":
        if st.button("Réinitialiser TOUTES les règles IPTables et Base (Flush)", use_container_width=True):
            try:
                subprocess.run(["iptables", "-F", "INPUT"], check=True)
            except Exception:
                pass
            db_manager.flush_banned_ips_in_db()
            try:
                pfsense_control_api.flush_pfsense_blocklist()
            except Exception:
                pass
            st.success("Tables de filtrage réinitialisées avec succès.")
            time.sleep(1)
            st.rerun()

# ==========================================
# VUE 5 : ADMINISTRATION (Réservé Admin SOC)
# ==========================================
elif menu == "Administration":
    st.markdown("### <i class='fa-solid fa-user-gear icon-blue'></i> Gestion des Utilisateurs du SOC", unsafe_allow_html=True)
    col_u1, col_u2 = st.columns(2)

    with col_u1:
        st.markdown("#### Créer un Compte Utilisateur")
        with st.form("add_user_form", clear_on_submit=True):
            new_username = st.text_input("Nom d'utilisateur")
            new_password = st.text_input("Mot de passe", type="password")
            new_role = st.selectbox("Rôle", options=["Opérateur SOC", "Administrateur SOC"])
            btn_add = st.form_submit_button("Créer le compte", use_container_width=True)
            if btn_add:
                if new_username.strip() and new_password.strip():
                    if db_manager.add_user(new_username.strip(), new_password.strip(), new_role):
                        st.success(f"Utilisateur '{new_username}' créé avec succès.")
                        time.sleep(1)
                        st.rerun()
                    else:
                        st.error("Erreur : Nom d'utilisateur déjà pris ou problème BDD.")
                else:
                    st.warning("Veuillez remplir tous les champs.")

    with col_u2:
        st.markdown("#### Comptes Enregistrés")
        users_data = db_manager.get_all_users()
        rows = users_data.itertuples(index=False) if hasattr(users_data, "itertuples") else (users_data or [])
        active_users, inactive_users = [], []
        for u in rows:
            uname = u.username if hasattr(u, "username") else u.get("username")
            urole = u.role if hasattr(u, "role") else u.get("role")
            ustat = getattr(u, "status", None) if hasattr(u, "status") else u.get("status")
            (active_users if ustat == "ACTIVE" else inactive_users).append((uname, urole))

        st.write("**Comptes Actifs**")
        st.table(pd.DataFrame(active_users, columns=["Utilisateur", "Rôle"]) if active_users else pd.DataFrame(columns=["Utilisateur", "Rôle"]))
        deactivable = [u for u, _ in active_users if u != st.session_state["user"]]
        if deactivable:
            target = st.selectbox("Désactiver un compte", options=deactivable, key="deact_select")
            if st.button("Désactiver le compte"):
                db_manager.deactivate_user(target)
                st.success(f"Compte '{target}' désactivé.")
                time.sleep(1)
                st.rerun()

        st.write("**Comptes Désactivés**")
        st.table(pd.DataFrame(inactive_users, columns=["Utilisateur", "Rôle"]) if inactive_users else pd.DataFrame(columns=["Utilisateur", "Rôle"]))
        if inactive_users:
            target_r = st.selectbox("Réactiver un compte", options=[u for u, _ in inactive_users], key="react_select")
            if st.button("Réactiver le compte"):
                reactivate_user(target_r)
                st.success(f"Compte '{target_r}' réactivé.")
                time.sleep(1)
                st.rerun()

# --- AUTO-RAFRAÎCHISSEMENT ---
if auto_refresh:
    time.sleep(refresh_interval)
    try:
        st.rerun()
    except Exception:
        pass
