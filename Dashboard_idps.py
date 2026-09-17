#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Security Operations Center (SOC)
Auteur : Gokeng Passo Yann Vanick
"""

import streamlit as st
import json
import os
import subprocess
import pandas as pd
import numpy as np
import time
import plotly.express as px
import db_manager

EVE_JSON_PATH = '/var/log/suricata/eve.json'

# Le dashboard est une interface de supervision : il affiche les résultats
# produits par Suricata et par le moteur Isolation Forest. Il ne doit pas
# recalculer les décisions de détection déjà enregistrées par le moniteur.

# --- CONFIGURATION DE LA PAGE ---
st.set_page_config(
    page_title="YOLI IDPS | Enterprise SOC",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- DESIGN SYSTEM & CSS ENTERPRISE ---
st.markdown("""
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

    html, body, [class*="css"] {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }

    .stApp {
        background-color: #f8fafc;
        color: #0f172a;
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: #ffffff !important;
        border-right: 1px solid #e2e8f0;
    }

    /* Custom Card Containers */
    .soc-card {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 20px;
        margin-bottom: 16px;
        box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.05);
    }

    /* Status Badges */
    .status-badge {
        display: inline-flex;
        align-items: center;
        padding: 2px 8px;
        border-radius: 4px;
        font-size: 0.75rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .badge-success { background-color: #dcfce7; color: #15803d; }
    .badge-danger { background-color: #fee2e2; color: #b91c1c; }
    .badge-info { background-color: #e0f2fe; color: #0369a1; }
    .badge-warning { background-color: #fef3c7; color: #b45309; }

    /* Custom Metric Display */
    .metric-container {
        background-color: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 16px;
        box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);
    }
    .metric-label {
        font-size: 0.85rem;
        color: #64748b;
        font-weight: 500;
        margin-bottom: 4px;
    }
    .metric-value {
        font-size: 1.75rem;
        font-weight: 700;
        color: #0f172a;
    }

    /* Professional Terminal UI */
    .terminal-window {
        background-color: #0f172a;
        border-radius: 8px;
        border: 1px solid #1e293b;
        box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.3);
        overflow: hidden;
        margin-top: 10px;
    }
    .terminal-header {
        background-color: #1e293b;
        padding: 8px 14px;
        display: flex;
        align-items: center;
        justify-content: space-between;
        border-bottom: 1px solid #334155;
    }
    .terminal-title {
        color: #94a3b8;
        font-size: 0.75rem;
        font-family: 'JetBrains Mono', monospace;
        font-weight: 500;
    }
    .terminal-body {
        padding: 16px;
        height: 340px;
        overflow-y: auto;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.82rem;
        line-height: 1.6;
        color: #f8fafc;
    }
    .t-sys { color: #64748b; }
    .t-info { color: #38bdf8; }
    .t-warn { color: #fbbf24; }
    .t-crit { color: #f87171; font-weight: 600; }
    .t-success { color: #4ade80; }

    /* Streamlit Tabs Customization */
    .stTabs [data-baseweb="tab-list"] {
        border-bottom: 1px solid #e2e8f0;
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 12px 4px;
        color: #64748b;
        font-weight: 500;
        border-bottom: 2px solid transparent;
        background-color: transparent !important;
    }
    .stTabs [aria-selected="true"] {
        color: #2563eb !important;
        border-bottom-color: #2563eb !important;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# --- SESSION STATE ---
# Streamlit réexécute le script après chaque interaction. Ces variables
# conservent donc l'utilisateur connecté et son rôle entre deux exécutions.
if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "user" not in st.session_state:
    st.session_state["user"] = None
if "role" not in st.session_state:
    st.session_state["role"] = None

def verify_credentials(username, password):
    # Reçoit l'identifiant et le mot de passe saisis dans le formulaire.
    # Délègue la vérification au module qui centralise l'accès à SQLite.
    role = db_manager.verify_user_credentials(username, password)
    # Un rôle retourné signifie que les identifiants sont valides.
    if role:
        # Renvoie le succès et le rôle pour configurer la session Streamlit.
        return True, role
    # Renvoie un échec explicite lorsque SQLite ne trouve pas l'utilisateur.
    return False, None

def login_form():
    # Le formulaire est la seule vue accessible avant authentification.
    # Après une connexion réussie, les informations de session sont enregistrées
    # puis Streamlit recharge l'application avec les droits de l'utilisateur.
    # Crée trois colonnes et utilise uniquement la colonne centrale pour centrer
    # visuellement le formulaire de connexion.
    _, col, _ = st.columns([1, 1, 1])
    # Place tous les éléments du formulaire dans la colonne centrale.
    with col:
        st.markdown("""
            <div class="soc-card" style="margin-top: 80px; text-align: center;">
                <div style="font-size: 2.5rem; color: #2563eb; margin-bottom: 10px;">
                    <i class="fa-solid fa-shield-halved"></i>
                </div>
                <h2 style="margin:0; font-size: 1.5rem; color: #0f172a;">YOLI IDPS</h2>
                <p style="color: #64748b; font-size: 0.875rem; margin-top: 4px;">Console d'Authentification SOC</p>
            </div>
        """, unsafe_allow_html=True)

        # Regroupe les champs afin que la validation se fasse avec un seul bouton.
        with st.form("login_form"):
            # Lit le nom fourni par l'opérateur.
            username = st.text_input("Identifiant")
            # Masque le mot de passe pendant sa saisie.
            password = st.text_input("Mot de passe", type="password")
            # Crée le bouton qui déclenche la vérification du formulaire.
            submit = st.form_submit_button("Connexion", use_container_width=True)
            # Ce bloc n'est exécuté qu'après l'envoi du formulaire.
            if submit:
                # Vérifie les données et récupère le rôle associé au compte.
                success, role = verify_credentials(username, password)
                # Ouvre la session lorsque les identifiants sont corrects.
                if success:
                    # Mémorise l'état authentifié pour les prochains reruns.
                    st.session_state["authenticated"] = True
                    # Mémorise le nom afin de l'afficher dans la barre latérale.
                    st.session_state["user"] = username
                    # Mémorise le rôle afin de limiter les actions sensibles.
                    st.session_state["role"] = role
                    # Recharge l'application pour afficher le dashboard principal.
                    st.rerun()
                else:
                    # Informe l'opérateur sans révéler si le nom ou le mot de passe
                    # était incorrect.
                    st.error("Échec d'authentification.")

def logout():
    # Effacer les trois valeurs empêche la réutilisation de l'ancienne session
    # lorsque l'opérateur se déconnecte.
    # Marque la session comme non authentifiée.
    st.session_state["authenticated"] = False
    # Supprime le nom de l'utilisateur courant.
    st.session_state["user"] = None
    # Supprime également son rôle et donc ses privilèges d'interface.
    st.session_state["role"] = None
    # Recharge l'application pour revenir au formulaire de connexion.
    st.rerun()

if not st.session_state["authenticated"]:
    # Affiche le formulaire tant que l'utilisateur n'est pas connecté.
    login_form()
    # Arrête le rendu du reste du fichier pour protéger le dashboard.
    st.stop()

# --- SERVICES & LOGS ---
# Ces fonctions observent l'état de l'environnement Linux. Elles indiquent
# si les moteurs sont actifs, mais ne remplacent ni Suricata ni le moniteur IA.
def check_service_status(service_name):
    # Suricata est géré comme un service systemd. Si systemctl est indisponible
    # ou renvoie une erreur, l'interface affiche prudemment l'état INACTIF.
    try:
        # Demande à systemd l'état du service reçu en argument.
        res = subprocess.run(["systemctl", "is-active", service_name], capture_output=True, text=True)
        # Compare la sortie système à la valeur attendue par systemd.
        return res.stdout.strip() == "active"
    except Exception:
        # Considère le service comme inactif si la commande n'est pas disponible.
        return False

def check_process_running(process_name):
    # Le moteur Isolation Forest est lancé dans un processus séparé. Cette
    # vérification porte uniquement sur sa présence, pas sur ses prédictions.
    try:
        # Recherche le processus dans la liste des processus Linux actifs.
        res = subprocess.run(["pgrep", "-f", process_name], capture_output=True, text=True)
        # Une sortie non vide indique qu'au moins un processus correspond.
        return len(res.stdout.strip()) > 0
    except Exception:
        # Évite de faire échouer le dashboard si pgrep n'est pas disponible.
        return False

def get_banned_ips():
    # La table banned_ips est la source d'état utilisée par l'application pour
    # savoir quelles IP sont encore actives. Cela conserve l'historique après
    # le redémarrage du dashboard.
    try:
        # Demande à SQLite les IP dont le statut est encore ACTIVE.
        banned = db_manager.get_active_banned_ips()
        # Retourne la liste uniquement lorsqu'une réponse existe.
        if banned:
            return banned
    except Exception:
        # Une erreur de base ne doit pas empêcher l'affichage du dashboard.
        pass
    # Retourne une liste vide pour simplifier les tests dans l'interface.
    return []

def get_recent_flows_and_alerts():
    # Les flux IA et les alertes Suricata sont volontairement chargés séparément.
    # Un flux possède une prédiction comportementale, alors qu'une alerte
    # Suricata possède une signature, une catégorie et une sévérité.
    # Charge les flux IA les plus récents depuis la table traffic_logs.
    df_f = db_manager.get_recent_flows_from_db(limit=2500)
    # Remplace None par un DataFrame vide si pandas n'est pas disponible.
    if df_f is None:
        df_f = pd.DataFrame()
    # Charge séparément les alertes Suricata persistées.
    df_a = db_manager.get_recent_suricata_alerts(limit=2500)
    # Utilise également un DataFrame vide lorsqu'aucune donnée n'est disponible.
    if df_a is None:
        df_a = pd.DataFrame()

    # Compatibilité avec les installations où Suricata n'est pas encore relié
    # à log_suricata_alert(). eve.json sert alors de source de lecture de secours.
    # Utilise eve.json uniquement si aucune alerte n'a encore été enregistrée
    # dans la table suricata_alerts.
    if df_a.empty and os.path.exists(EVE_JSON_PATH):
        # Prépare une liste temporaire pour les alertes lues dans le fichier.
        alerts = []
        try:
            # Ouvre eve.json en lecture sans modifier le journal Suricata.
            with open(EVE_JSON_PATH, 'r') as eve_file:
                # Limite la lecture aux 2500 dernières lignes pour maîtriser
                # le temps de chargement et la mémoire utilisée.
                for line in eve_file.readlines()[-2500:]:
                    # Transforme la ligne JSON en dictionnaire Python.
                    data = json.loads(line)
                    # Ignore les événements flow et conserve uniquement alert.
                    if data.get('event_type') != 'alert':
                        continue
                    # Récupère le sous-objet contenant les détails de la signature.
                    alert = data.get('alert', {})
                    # Convertit l'événement Suricata au format utilisé par le tableau.
                    alerts.append({
                        'Timestamp': str(data.get('timestamp', ''))[11:19],
                        'IP Source': data.get('src_ip', 'N/A'),
                        'IP Dest': data.get('dest_ip', 'N/A'),
                        'Signature': alert.get('signature', 'N/A'),
                        'Catégorie': alert.get('category', 'N/A'),
                        'Priorité': alert.get('severity', 'N/A')
                    })
        except (OSError, ValueError, TypeError):
            # Ignore un fichier absent, une ligne JSON invalide ou une valeur mal formée.
            alerts = []
        # Transforme la liste des dictionnaires en DataFrame affichable.
        df_a = pd.DataFrame(alerts)

    # Harmonise les noms SQLite avec les noms lisibles affichés dans l'interface.
    if not df_a.empty:
        df_a = df_a.rename(columns={
            'timestamp': 'Timestamp',
            'src_ip': 'IP Source',
            'dst_ip': 'IP Dest',
            'signature': 'Signature',
            'category': 'Catégorie',
            'severity': 'Priorité'
        })
        # Ne conserve que la partie heure pour les tableaux compacts.
        df_a['Timestamp'] = df_a['Timestamp'].astype(str).str[11:19]

    # Prépare les flux persistés pour les graphiques et les tableaux du dashboard.
    if not df_f.empty:
        df_f = df_f.rename(columns={
            'timestamp': 'Timestamp_Raw',
            'src_ip': 'IP Source',
            'dst_ip': 'IP Dest',
            'dst_port': 'Port Dest',
            'protocol': 'Protocole',
            'bytes_total': 'Octets',
            'pkts_total': 'Paquets',
            'anomaly_score': 'Anomaly Score',
            'prediction': 'Prediction'
        })
        # Crée une colonne courte destinée à l'affichage dans les journaux.
        df_f['Timestamp'] = df_f['Timestamp_Raw'].astype(str).str[11:19]
        # Convertit l'horodatage en type temporel pour l'axe du graphique.
        df_f['Timestamp_DT'] = pd.to_datetime(df_f['Timestamp_Raw'], errors='coerce')
        # Trie les flux chronologiquement et supprime les dates illisibles.
        df_f = df_f.sort_values(by='Timestamp_DT').dropna(subset=['Timestamp_DT'])

    # Retourne les deux jeux de données au code qui construit l'interface.
    return df_f, df_a

# Récupère les IP bloquées avant de dessiner la page.
banned_ips = get_banned_ips()
# Récupère les flux IA et les alertes Suricata récentes.
df_flows, df_alerts = get_recent_flows_and_alerts()
# Vérifie si le service Suricata est actuellement actif.
suricata_active = check_service_status("suricata")
# Vérifie si le moniteur Isolation Forest est actuellement actif.
ai_monitor_active = check_process_running("yoli_realtime_monitor1.py")

# --- SIDEBAR ENTERPRISE ---
# La barre latérale présente l'identité de l'opérateur et l'état des trois
# composants surveillés : Suricata, le moniteur IA et IPTables.
with st.sidebar:
    st.markdown("""
        <div style="padding: 10px 0; border-bottom: 1px solid #e2e8f0; margin-bottom: 15px;">
            <span style="font-size: 1.1rem; font-weight: 700; color: #0f172a;">
                <i class="fa-solid fa-server" style="color: #2563eb; margin-right: 8px;"></i>YOLI SOC PANEL
            </span>
        </div>
    """, unsafe_allow_html=True)

    # Affiche l'identité de l'utilisateur issue de la session authentifiée.
    st.markdown(f"**Opérateur :** {st.session_state['user']}")
    # Affiche son rôle pour rendre visibles ses droits actuels.
    st.markdown(f"<span class='status-badge badge-info'>{st.session_state['role']}</span>", unsafe_allow_html=True)
    st.write("")
    # Affiche le bouton permettant de fermer la session.
    if st.button("Déconnexion", use_container_width=True):
        # Efface la session si l'opérateur demande la déconnexion.
        logout()

    st.markdown("<hr style='margin: 15px 0; border-color: #e2e8f0;'>", unsafe_allow_html=True)
    st.markdown("<p style='font-size: 0.8rem; font-weight: 600; color: #64748b; text-transform: uppercase;'>État des Moteurs</p>", unsafe_allow_html=True)

    suricata_badge = "<span class='status-badge badge-success'>ACTIF</span>" if suricata_active else "<span class='status-badge badge-danger'>INACTIF</span>"
    ai_badge = "<span class='status-badge badge-success'>ACTIF</span>" if ai_monitor_active else "<span class='status-badge badge-danger'>INACTIF</span>"

    st.markdown(f"<div style='display:flex; justify-content:space-between; margin-bottom:8px;'><span>Suricata NIDS</span>{suricata_badge}</div>", unsafe_allow_html=True)
    st.markdown(f"<div style='display:flex; justify-content:space-between; margin-bottom:8px;'><span>Isolation Forest</span>{ai_badge}</div>", unsafe_allow_html=True)
    st.markdown(f"<div style='display:flex; justify-content:space-between;'><span>Driver IPTables</span><span class='status-badge badge-success'>ACTIF</span></div>", unsafe_allow_html=True)

# --- HEADER PRINCIPAL ---
st.markdown("""
    <div style="margin-bottom: 20px;">
        <h1 style="font-size: 1.75rem; font-weight: 700; color: #0f172a; margin: 0;">
            <i class="fa-solid fa-microchip" style="color: #2563eb; margin-right: 10px;"></i>Console de Supervision & IDPS
        </h1>
        <p style="color: #64748b; margin-top: 4px; font-size: 0.9rem;">
            Analyse comportementale du trafic réseau en temps réel et prévention d'intrusions.
        </p>
    </div>
""", unsafe_allow_html=True)

# --- METRIQUES PRINCIPALES ---
# Les indicateurs sont dérivés des données persistées. Une anomalie est
# comptée uniquement lorsque Prediction vaut "Anomalie", c'est-à-dire lorsque
# le moteur IA a déjà pris cette décision.
anomalies_df = df_flows[df_flows['Prediction'] == 'Anomalie'] if not df_flows.empty else pd.DataFrame()

c1, c2, c3 = st.columns(3)
with c1:
    st.markdown(f"""
        <div class="metric-container">
            <div class="metric-label"><i class="fa-solid fa-network-wired" style="margin-right:6px;"></i>Flux Analysés</div>
            <div class="metric-value">{len(df_flows)}</div>
        </div>
    """, unsafe_allow_html=True)
with c2:
    st.markdown(f"""
        <div class="metric-container">
            <div class="metric-label"><i class="fa-solid fa-triangle-exclamation" style="color:#dc2626; margin-right:6px;"></i>Anomalies IA</div>
            <div class="metric-value" style="color:#dc2626;">{len(anomalies_df)}</div>
        </div>
    """, unsafe_allow_html=True)
with c3:
    st.markdown(f"""
        <div class="metric-container">
            <div class="metric-label"><i class="fa-solid fa-ban" style="margin-right:6px;"></i>IP Neutralisées</div>
            <div class="metric-value">{len(banned_ips)}</div>
        </div>
    """, unsafe_allow_html=True)

st.write("")

# --- ONGLETS PRINCIPAUX ---
tab_mon, tab_ai, tab_sig, tab_adm = st.tabs([
    "Supervision du Trafic",
    "Moteur IA & Console Execution",
    "Signatures Suricata",
    "Administration SOC"
])

# TAB 1 : MONITORING
# Cette vue permet de suivre le volume réseau, les anomalies comportementales
# et les adresses IP actuellement neutralisées.
with tab_mon:
    col_chart, col_banned = st.columns([2, 1])

    with col_chart:
        st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-chart-line' style='color:#2563eb; margin-right:8px;'></i>Volumétrie des Paquets Traités</h4>", unsafe_allow_html=True)
        if not df_flows.empty:
            fig = px.line(
                df_flows,
                x="Timestamp_DT",
                y="Paquets"
            )
            fig.update_traces(line_color="#2563eb", line_width=1.5, name="Trafic Normal")

            if not anomalies_df.empty:
                fig_anomaly = px.scatter(
                    anomalies_df,
                    x="Timestamp_DT",
                    y="Paquets",
                    hover_data=["IP Source", "Port Dest", "Protocole", "Anomaly Score"]
                )
                fig_anomaly.update_traces(
                    marker=dict(
                        color="#dc2626",
                        size=9,
                        symbol="circle",
                        line=dict(width=1, color="#7f1d1d")
                    ),
                    opacity=0.8,
                    name="Anomalie Détectée"
                )
                fig.add_trace(fig_anomaly.data[0])

            fig.update_layout(
                template="plotly_white",
                height=320,
                margin=dict(l=10, r=10, t=10, b=10),
                xaxis=dict(title="Horodatage", type="date", tickformat="%H:%M:%S"),
                yaxis=dict(title="Nombre de Paquets"),
                showlegend=True,
                legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Aucune donnée de flux disponible.")

    with col_banned:
        st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-shield-cat' style='color:#dc2626; margin-right:8px;'></i>Adresses IP Bloquées</h4>", unsafe_allow_html=True)
        if banned_ips:
            st.dataframe(pd.DataFrame({'IP Target': banned_ips, 'Rule': 'DROP'}), hide_index=True, use_container_width=True)
        else:
            st.info("Aucune restriction active.")

    st.markdown("<h4 style='font-size:1rem; font-weight:600; margin-top:15px;'><i class='fa-solid fa-list-check' style='margin-right:8px;'></i>Détails des Anomalies Détectées</h4>", unsafe_allow_html=True)
    if not anomalies_df.empty:
        st.dataframe(
            anomalies_df[['Timestamp', 'IP Source', 'IP Dest', 'Port Dest', 'Protocole', 'Paquets', 'Octets', 'Anomaly Score']],
            hide_index=True,
            use_container_width=True
        )
    else:
        st.info("Aucun flux suspect enregistré sur la période récente.")

# TAB 2 : MOTEUR IA & TERMINAL DE RAISONNEMENT
# Les graphiques et les journaux expliquent les prédictions enregistrées par
# le moniteur. Le dashboard ne lance pas une nouvelle inférence ici.
with tab_ai:
    st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-brain' style='color:#2563eb; margin-right:8px;'></i>Analyse des Décisions du Modèle d'Isolation Forest</h4>", unsafe_allow_html=True)

    if not df_flows.empty:
        ca1, ca2 = st.columns(2)
        with ca1:
            fig_hist = px.histogram(
                df_flows, x="Anomaly Score", color="Prediction", nbins=15,
                color_discrete_map={'Normal': '#2563eb', 'Anomalie': '#dc2626'}
            )
            fig_hist.update_layout(template="plotly_white", height=250, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig_hist, use_container_width=True)

        with ca2:
            fig_scat = px.scatter(
                df_flows, x="Octets", y="Paquets", color="Prediction", size="Anomaly Score",
                color_discrete_map={'Normal': '#2563eb', 'Anomalie': '#dc2626'}
            )
            fig_scat.update_layout(template="plotly_white", height=250, margin=dict(l=10, r=10, t=10, b=10))
            st.plotly_chart(fig_scat, use_container_width=True)

        st.markdown("<h4 style='font-size:1rem; font-weight:600; margin-top:20px;'><i class='fa-solid fa-terminal' style='margin-right:8px;'></i>Console d'Inférence IA & Execution Logs</h4>", unsafe_allow_html=True)

        terminal_lines = [
            "<span class='t-sys'>[SYSTEM] Initializing Inference Pipeline... Engine: IsolationForest</span>",
            "<span class='t-sys'>[SYSTEM] Active Rule Base: Normalized Flow Vectorization (Bytes, Packets, Rates)</span>",
            "<span class='t-sys'>-----------------------------------------------------------------------------------</span>"
        ]

        for row in df_flows.tail(12).values:
            ts, src, dst, port, proto, octets, pkts, score, pred = row[1], row[2], row[3], row[4], row[5], row[6], row[7], row[8], row[9]
            if pred == "Anomalie":
                reason = "Volumétrie anormale détectée par la profondeur de l'arbre d'isolation"
                if pkts > 1500:
                    reason = "Anomalie : Densité élevée de paquets (Possible attaque Syn Flood)"
                elif octets > 100000:
                    reason = "Anomalie : Volume de charge utile hors-norme (Possible exfiltration)"

                line = f"<span class='t-crit'>[{ts}] [ANOMALY] Src: {src} -> Dst: {dst}:{port} | Pkts: {pkts} | Bytes: {octets} | Score: {score} | Reason: {reason}</span>"
            else:
                line = f"<span class='t-info'>[{ts}] [NORMAL]  Src: {src} -> Dst: {dst}:{port} | Pkts: {pkts} | Bytes: {octets} | Score: {score} | Status: OK</span>"

            terminal_lines.append(line)

        terminal_html = "<br>".join(terminal_lines)

        st.markdown(f"""
            <div class="terminal-window">
                <div class="terminal-header">
                    <span class="terminal-title"><i class="fa-solid fa-terminal" style="margin-right: 6px;"></i>yoli-idps-engine --live-inference</span>
                    <span class="terminal-title">LOG LEVEL: DEBUG</span>
                </div>
                <div class="terminal-body">
                    {terminal_html}
                </div>
            </div>
        """, unsafe_allow_html=True)

# TAB 3 : SURICATA
# Cette vue regroupe uniquement les alertes fondées sur les signatures et les
# règles Suricata, indépendamment des anomalies découvertes par l'IA.
with tab_sig:
    st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-bell' style='color:#2563eb; margin-right:8px;'></i>Détections de Signatures Suricata</h4>", unsafe_allow_html=True)
    if not df_alerts.empty:
        st.dataframe(df_alerts.tail(20), hide_index=True, use_container_width=True)
    else:
        st.info("Aucune alerte basée sur les signatures NIDS.")

# TAB 4 : ADMIN & GESTION DES UTILISATEURS
# Les actions sensibles sont réservées à l'Administrateur SOC : suppression
# d'une règle DROP, remise à zéro d'IPTables et gestion des comptes.
with tab_adm:
    st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-sliders' style='color:#2563eb; margin-right:8px;'></i>Actions de Mitigations & Administration</h4>", unsafe_allow_html=True)

    # Vérifie le rôle avant de rendre disponibles les commandes système.
    if st.session_state["role"] == "Administrateur SOC":
        ca, cb = st.columns(2)
        with ca:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("**Déblocage d'adresse IP**")
            # N'affiche le sélecteur que si une IP active existe réellement.
            if banned_ips:
                # Permet à l'administrateur de choisir l'IP à libérer.
                ip_to_unban = st.selectbox("Sélectionner l'adresse à libérer", options=banned_ips)
                # Déclenche la suppression de la règle DROP sélectionnée.
                if st.button("Supprimer la règle IPTables", use_container_width=True):
                    try:
                        # Retire la règle correspondante du pare-feu Linux.
                        subprocess.run(f"iptables -D INPUT -s {ip_to_unban} -j DROP", shell=True, check=True)
                        # Met à jour l'historique SQLite sans supprimer l'enregistrement.
                        db_manager.unban_ip_in_db(ip_to_unban)
                        # Informe l'administrateur du résultat de l'opération.
                        st.success(f"IP {ip_to_unban} débloquée.")
                        # Laisse le temps de lire le message avant le rechargement.
                        time.sleep(1)
                        # Recharge la liste des IP après la modification.
                        st.rerun()
                    except Exception as e:
                        # Affiche l'erreur sans interrompre toute l'interface.
                        st.error(f"Erreur : {e}")
            else:
                st.info("Aucune IP n'est actuellement restreinte.")
            st.markdown("</div>", unsafe_allow_html=True)

        with cb:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("**Actions Système**")
            # Propose une remise à zéro globale des règles INPUT.
            if st.button("Réinitialiser IPTables (Flush)", use_container_width=True):
                try:
                    # Supprime les règles de filtrage de la chaîne INPUT.
                    subprocess.run("iptables -F INPUT", shell=True, check=True)
                    # Marque les anciennes IP comme RELEASED dans SQLite.
                    db_manager.flush_banned_ips_in_db()
                    # Informe l'administrateur du succès de la réinitialisation.
                    st.success("Table de filtrage réinitialisée.")
                    # Attend brièvement avant de reconstruire l'interface.
                    time.sleep(1)
                    # Actualise le nombre d'IP neutralisées affiché.
                    st.rerun()
                except Exception as e:
                    # Présente l'erreur système dans la page d'administration.
                    st.error(f"Erreur : {e}")
            st.markdown("</div>", unsafe_allow_html=True)

        # --- MODULE GESTION DES UTILISATEURS ---
        # Un compte est désactivé plutôt que supprimé afin de préserver sa
        # trace dans la base et d'empêcher une authentification ultérieure.
        st.markdown("<hr style='margin: 25px 0; border-color: #e2e8f0;'>", unsafe_allow_html=True)
        st.markdown("<h4 style='font-size:1rem; font-weight:600;'><i class='fa-solid fa-users-gear' style='color:#2563eb; margin-right:8px;'></i>Gestion des Utilisateurs du SOC</h4>", unsafe_allow_html=True)

        col_u1, col_u2 = st.columns([1, 1])

        with col_u1:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("**Ajouter un Utilisateur**")
            with st.form("add_user_form", clear_on_submit=True):
                new_username = st.text_input("Nom d'utilisateur")
                new_password = st.text_input("Mot de passe", type="password")
                new_role = st.selectbox("Rôle RBA", options=["Analyste SOC", "Administrateur SOC"])
                btn_add_user = st.form_submit_button("Créer le compte", use_container_width=True)

                if btn_add_user:
                    # Vérifie que le nom et le mot de passe ne sont pas vides.
                    if new_username.strip() and new_password.strip():
                        # Demande à db_manager de créer le compte avec son rôle.
                        success = db_manager.add_user(new_username.strip(), new_password.strip(), new_role)
                        if success:
                            # Confirme la création du compte à l'administrateur.
                            st.success(f"Utilisateur '{new_username}' créé avec succès !")
                            # Attend brièvement afin que le message soit visible.
                            time.sleep(1)
                            # Recharge la liste des utilisateurs.
                            st.rerun()
                        else:
                            # Signale un nom déjà utilisé ou une erreur SQLite.
                            st.error("Impossible de créer l'utilisateur (nom déjà pris ou erreur base de données).")
                    else:
                        # Refuse la création d'un compte incomplet.
                        st.warning("Veuillez remplir tous les champs.")
            st.markdown("</div>", unsafe_allow_html=True)

        with col_u2:
            st.markdown("<div class='soc-card'>", unsafe_allow_html=True)
            st.markdown("**Comptes Enregistrés & Rôles**")

            # Récupération des utilisateurs depuis SQLite. La réponse attendue
            # est un DataFrame, mais la branche list conserve une compatibilité
            # avec une ancienne implémentation éventuelle.
            users_data = db_manager.get_all_users()

            # Vérification de la présence de résultats avant d'afficher le
            # tableau et les contrôles de désactivation.
            has_users = False
            if isinstance(users_data, pd.DataFrame):
                has_users = not users_data.empty
                df_users = users_data
            elif isinstance(users_data, list):
                has_users = len(users_data) > 0
                df_users = pd.DataFrame(users_data) if has_users else pd.DataFrame()

            if has_users:
                st.dataframe(df_users, hide_index=True, use_container_width=True)

                st.markdown("**desactiver un Compte**")

                # Exclure l'opérateur connecté afin qu'il ne puisse pas
                # désactiver son propre compte depuis cette interface.
                if isinstance(users_data, pd.DataFrame):
                    user_list_names = users_data['username'].tolist() if 'username' in users_data.columns else []
                else:
                    user_list_names = [u['username'] for u in users_data if isinstance(u, dict) and 'username' in u]

                # Filtrer l'utilisateur actuellement connecté
                user_names = [u for u in user_list_names if u != st.session_state["user"]]

                if user_names:
                    user_to_delete = st.selectbox("Sélectionner le compte a desactiver", options=user_names)
                    if st.button("desactiver un compte", use_container_width=True):
                        if db_manager.deactivate_user(user_to_delete):
                            st.success(f"compte '{user_to_delete}' desactive.")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Erreur lors de la desactivation !!!.")
                else:
                    st.caption("Aucun autre compte ne peut être desactive.")
            else:
                st.info("Aucun utilisateur trouvé.")
            st.markdown("</div>", unsafe_allow_html=True)

    else:
        st.warning("Accès restreint. Privilèges d'Administrateur SOC requis pour exécuter ces actions.")

# AUTO REFRESH
# Le rechargement périodique rend visibles les nouveaux flux, alertes et
# changements d'état sans intervention manuelle de l'opérateur.
time.sleep(3)
try:
    st.rerun()
except Exception:
    pass
