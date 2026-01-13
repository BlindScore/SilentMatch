"""
client.py
The Bank's Security Module.
Handles Multi-Attribute Identity (Email, SIN, Phone, Name).
"""
import json
import secrets
import math
import re
from config import PRIME_MODULUS, Colors
from crypto_engine import OPRFMath

class BankSecurityModule:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self._blinding_factor = self._generate_valid_blinding_factor()

    def _generate_valid_blinding_factor(self) -> int:
        phi = PRIME_MODULUS - 1
        while True:
            r = secrets.randbelow(phi)
            if r > 1 and math.gcd(r, phi) == 1:
                return r

    def _check_server_health(self, server_node) -> bool:
        response = server_node.authenticate(self.api_key)
        if response["status"] == "OK":
            return True
        elif response["status"] == "OUTDATED":
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 SERVER ALERT: {response['msg']}{Colors.ENDC}")
            return False
        return False

    # --- Data Normalization ---
    def normalize_input(self, data_type: str, value: str) -> str:
        if not value: return None
        
        value = str(value).lower().strip()
        
        if data_type == "email":
            clean = value.replace(" ", "")
            
        elif data_type == "phone":
            clean = re.sub(r'\D', '', value) 
            
        elif data_type == "sin" or data_type == "nas":
            clean = re.sub(r'\D', '', value)
            
        elif data_type == "name":
            clean = re.sub(r'\s+', ' ', value)
            
        else:
            clean = value

        return f"{data_type}:{clean}"

    def process_ingestion(self, json_file_path: str, server_node) -> None:
        auth = server_node.authenticate(self.api_key)
        if auth["status"] == "ERROR": return

        try:
            with open(json_file_path, 'r') as f:
                raw_data = json.load(f)
        except FileNotFoundError:
            print(f"{Colors.RED}Error file not found.{Colors.ENDC}")
            return

        print(f"🔒 [CLIENT] Processing ingestion for {len(raw_data)} profiles...")
        data_to_finalize = []

        WATCHED_FIELDS = ["email", "phone", "sin", "name"]

        for record in raw_data:
            for field in WATCHED_FIELDS:
                if field in record and record[field]:

                    # 1. Normalization
                    clean_val = self.normalize_input(field, record[field])
                    
                    # 2. OPRF Flow
                    blinded_val = OPRFMath.mod_pow(OPRFMath.map_string_to_group(clean_val), self._blinding_factor)
                    signed_val, key_v = server_node.sign_blinded_request(blinded_val)
                    inv_r = OPRFMath.mod_inverse(self._blinding_factor)
                    final_sig = hex(OPRFMath.mod_pow(signed_val, inv_r))[2:]

                    data_to_finalize.append({
                        "signature": final_sig,
                        "risk": record['risk'],
                        "role": record['role'],
                        "key_version": key_v
                    })

        server_node.register_incident_batch(self.api_key, data_to_finalize)
        print(f"{Colors.GREEN}✅ Ingestion complete ({len(data_to_finalize)} attributes secured).{Colors.ENDC}")


    def process_verification(self, json_file_path: str, server_node):
        if not self._check_server_health(server_node):
             pass

        try:
            with open(json_file_path, 'r') as f:
                applicants = json.load(f)
        except FileNotFoundError: return

        print(f"🕵️  [CLIENT] Verifying {len(applicants)} applicants (Multi-Attribute Scan)...")
        
        sig_lookup = {} 
        signatures_to_check = []
        WATCHED_FIELDS = ["email", "phone", "sin", "name"]

        for app in applicants:
            app_id = app.get("id", "UNKNOWN")
            
            for field in WATCHED_FIELDS:
                if field in app and app[field]:
                    
                    # 1. Normalisation
                    clean_val = self.normalize_input(field, app[field])
                    
                    # 2. Crypto
                    blinded_val = OPRFMath.mod_pow(OPRFMath.map_string_to_group(clean_val), self._blinding_factor)
                    signed_val, _ = server_node.sign_blinded_request(blinded_val)
                    inv_r = OPRFMath.mod_inverse(self._blinding_factor)
                    final_sig = hex(OPRFMath.mod_pow(signed_val, inv_r))[2:]
                    
                    signatures_to_check.append(final_sig)
                    
                    sig_lookup[final_sig] = {
                        "app_id": app_id, 
                        "field": field, 
                        "value": app[field] # Optionnal
                    }

        results = server_node.check_status_batch(signatures_to_check)

        print(f"\n{Colors.HEADER}--- ANALYSIS REPORT ---{Colors.ENDC}")
        
        alerts_by_app = {}

        for sig, res in results.items():
            if res['status'] == "FOUND":
                info = sig_lookup[sig]
                app_id = info["app_id"]
                
                if app_id not in alerts_by_app:
                    alerts_by_app[app_id] = []
                
                alerts_by_app[app_id].append({
                    "field": info["field"],
                    "risk": res['data']['risk'],
                    "role": res['data']['role']
                })

        for app in applicants:
            aid = app.get("id")
            if aid in alerts_by_app:
                print(f"{Colors.RED}[ALERT] Applicant {aid}{Colors.ENDC}")
                for alert in alerts_by_app[aid]:
                    print(f"   -> Match on {alert['field'].upper()}: {alert['risk']} ({alert['role']})")
                print(f"   -> Action: BLOCK / REVIEW")
            else:
                print(f"{Colors.GREEN}[PASS]  Applicant {aid} - No match found.{Colors.ENDC}")