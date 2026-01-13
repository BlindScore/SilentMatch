"""
server.py
The SilentMatch API Node.
Manages Key Rotation and Versioned Ledgers.
"""
import json
import secrets
import os
from typing import Dict, Tuple
from config import PRIME_MODULUS, RiskType, ActorRole, LEDGER_DIR, KEYS_FILE, CLIENTS_FILE
from crypto_engine import OPRFMath

class KeyManager:
    def __init__(self):
        self._keys = {}
        self.current_version = 0
        self.load_keys()
    def load_keys(self):
        if os.path.exists(KEYS_FILE):
            with open(KEYS_FILE, 'r') as f:
                data = json.load(f)
                self.current_version = data["current_version"]
                self._keys = {int(k): int(v) for k, v in data["keys"].items()}
        else:
            self.rotate()
    def save_keys(self):
        with open(KEYS_FILE, 'w') as f:
            json.dump({"current_version": self.current_version, "keys": self._keys}, f, indent=4)
    def rotate(self):
        self.current_version += 1
        self._keys[self.current_version] = secrets.randbelow(PRIME_MODULUS - 1)
        self.save_keys()
        return self.current_version
    def get_key(self, version: int) -> int:
        return self._keys.get(version)


class ClientManager:
    def __init__(self):
        self.clients = {}
        self.load_clients()
    def load_clients(self):
        if os.path.exists(CLIENTS_FILE):
            with open(CLIENTS_FILE, 'r') as f:
                self.clients = json.load(f)
    def save_clients(self):
        with open(CLIENTS_FILE, 'w') as f:
            json.dump(self.clients, f, indent=4)
    def create_api_key(self, bank_name: str) -> str:
        api_key = secrets.token_hex(16)
        self.clients[api_key] = {"name": bank_name, "last_sync_version": 0}
        self.save_clients()
        return api_key
    # Remove in Production
    def get_all_clients(self):
        """Retourne une liste de tuples (Nom, API_KEY) pour l'affichage."""
        return [(info['name'], key) for key, info in self.clients.items()]
    def update_sync_status(self, api_key: str, key_version: int):
        if api_key in self.clients:
            self.clients[api_key]["last_sync_version"] = key_version
            self.save_clients()
    def check_health(self, api_key: str, current_server_version: int) -> dict:
        if api_key not in self.clients: return {"status": "ERROR", "msg": "Invalid API Key"}
        client_ver = self.clients[api_key]["last_sync_version"]
        if client_ver < current_server_version:
            return {"status": "OUTDATED", "msg": f"CRITICAL: You are on v{client_ver}. Server is on v{current_server_version}. PREVIOUS DATA IS ARCHIVED/INVALID."}
        return {"status": "OK", "msg": "Client is synchronized."}


class SilentMatchNode:
    def __init__(self):
        self.kms = KeyManager()
        self.client_mgr = ClientManager()
        self._ledger = {}
        self.load_current_db()

    @property
    def current_db_path(self):
        """Returns path like 'data/ledgers/v1.json' based on active key"""
        return f"{LEDGER_DIR}/v{self.kms.current_version}.json"

    def load_current_db(self):
        """Loads the ledger file corresponding to the active key."""
        path = self.current_db_path
        if os.path.exists(path):
            with open(path, 'r') as f:
                self._ledger = json.load(f)
            print(f"📦 [SERVER] Loaded Active Ledger: {path}")
        else:
            self._ledger = {}
            print(f"🆕 [SERVER] Initialized New Ledger: {path}")
            self.save_db()

    def save_db(self):
        """Saves memory to the VERSIONED file."""
        with open(self.current_db_path, 'w') as f:
            json.dump(self._ledger, f, indent=4)

    def rotate_server(self):
        """
        Orchestrates the rotation:
        1. Rotate Key (v1 -> v2)
        2. Drop old DB from memory (Archived in v1.json)
        3. Start fresh DB (v2.json)
        """
        new_v = self.kms.rotate()
        self._ledger = {}
        self.save_db()
        print(f"🔄 [SERVER] Rotated to Version {new_v}. Previous ledger archived.")
        return new_v

    # --- API ---

    def authenticate(self, api_key: str) -> dict:
        return self.client_mgr.check_health(api_key, self.kms.current_version)

    def sign_blinded_request(self, blinded_val_int: int) -> Tuple[int, int]:
        current_v = self.kms.current_version
        key = self.kms.get_key(current_v)
        signed_val = OPRFMath.mod_pow(blinded_val_int, key)
        return signed_val, current_v

    def register_incident_batch(self, api_key: str, batch_data: list):
        for item in batch_data:
            sig = item['signature']
            self._ledger[sig] = {
                "risk": item['risk'],
                "role": item['role'],
                "key_version": item['key_version']
            }
        self.save_db()
        
        current_v = self.kms.current_version
        self.client_mgr.update_sync_status(api_key, current_v)
        print(f"💾 [SERVER] Data saved to v{current_v}.json & Client updated.")

    def check_status_batch(self, signatures: list) -> Dict[str, dict]:
        results = {}
        for sig in signatures:
            if sig in self._ledger:
                entry = self._ledger[sig]
                results[sig] = {"status": "FOUND", "data": entry}
            else:
                results[sig] = {"status": "CLEAN"}
        return results