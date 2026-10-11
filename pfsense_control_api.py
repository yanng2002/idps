#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
YOLI TECHNOLOGIES - Pont de prevention vers pfSense API REST
"""

import os
import requests
import urllib3
import sys

from dotenv import load_dotenv
load_dotenv()


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PFSENSE_HOST = "http://192.168.40.1"
PFSENSE_API_KEY = os.environ.get("PFSENSE_API_KEY")

if not PFSENSE_API_KEY:
    print("[PFSENSE][ERREUR] La variable d'environnement PFSENSE_API_KEY n'est pas definie. ")
    sys.exit(1)

ALIAS_NAME = "BLOCKLIST"
ALIASES_LIST_ENDPOINT = f"{PFSENSE_HOST}/api/v2/firewall/aliases"
ALIAS_ENDPOINT = f"{PFSENSE_HOST}/api/v2/firewall/alias"

REQUEST_TIMEOUT_SECONDS = 8
VERIFY_TLS = False


def _headers():
    return {
        "x-api-key": PFSENSE_API_KEY,
        "Content-Type": "application/json",
    }


def _get_current_alias():
    try:
        resp = requests.get(
            ALIASES_LIST_ENDPOINT,
            headers=_headers(),
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        if resp.status_code != 200:
            print(f"[PFSENSE][ERREUR] Listage des alias echoue : "
                  f"HTTP {resp.status_code} - {resp.text.strip()}")
            return None

        all_aliases = resp.json().get("data", [])
        alias = next((a for a in all_aliases if a.get("name") == ALIAS_NAME), None)

        if alias is None:
            print(f"[PFSENSE][ERREUR] Alias '{ALIAS_NAME}' introuvable.")
            return None

        if isinstance(alias.get("address"), str):
            alias["address"] = alias["address"].split()
        if not isinstance(alias.get("detail"), list):
            alias["detail"] = []

        return alias
    except requests.exceptions.RequestException as e:
        print(f"[PFSENSE][ERREUR] Connexion API impossible : {e}")
        return None


def _patch_alias(alias_obj):
    # address et detail doivent toujours avoir la meme longueur, sinon
    # l'API refuse la requete (TOO_MANY_ALIAS_DETAILS).
    addr_len = len(alias_obj.get("address", []))
    alias_obj["detail"] = (alias_obj.get("detail", []) + [""] * addr_len)[:addr_len]

    try:
        resp = requests.patch(
            ALIAS_ENDPOINT,
            json=alias_obj,
            headers=_headers(),
            timeout=REQUEST_TIMEOUT_SECONDS,
            verify=VERIFY_TLS,
        )
        if resp.status_code == 200:
            return True
        print(f"[PFSENSE][ERREUR] PATCH {ALIAS_NAME} echoue : "
              f"HTTP {resp.status_code} - {resp.text.strip()}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"[PFSENSE][ERREUR] Echec de la requete API : {e}")
        return False


def block_ip_on_pfsense(ip_address):
    alias = _get_current_alias()
    if alias is None:
        return False
    if ip_address in alias.get("address", []):
        print(f"[PFSENSE] IP {ip_address} deja presente dans {ALIAS_NAME}.")
        return True

    alias["address"] = alias.get("address", []) + [ip_address]
    alias["detail"] = alias.get("detail", []) + ["Bloque par YOLI IDPS"]
    if _patch_alias(alias):
        print(f"[PFSENSE] IP {ip_address} ajoutee a {ALIAS_NAME} (bloquee au niveau du WAN).")
        return True
    return False


def unblock_ip_on_pfsense(ip_address):
    alias = _get_current_alias()
    if alias is None:
        return False
    if ip_address not in alias.get("address", []):
        return True

    idx = alias["address"].index(ip_address)
    alias["address"].pop(idx)
    if idx < len(alias.get("detail", [])):
        alias["detail"].pop(idx)
    return _patch_alias(alias)


def flush_pfsense_blocklist():
    alias = _get_current_alias()
    if alias is None:
        return False
    alias["address"] = []
    alias["detail"] = []
    return _patch_alias(alias)


def test_connection():
    if not PFSENSE_API_KEY:
        print("[PFSENSE][ECHEC] Variable d'environnement PFSENSE_API_KEY non definie.")
        return False

    alias = _get_current_alias()
    if alias is None:
        return False

    current = alias.get("address", [])
    print(f"[PFSENSE] Connexion API OK. Contenu actuel de {ALIAS_NAME} :")
    print(", ".join(current) if current else "(alias vide)")
    return True


if __name__ == "__main__":
    test_connection()
