"""
client.py
The Bank's Security Module.
"""
import json
import secrets
import math
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
        """
        Demande au serveur : 'Suis-je à jour ?'
        Retourne False si on doit arrêter ou faire attention.
        """
        response = server_node.authenticate(self.api_key)
        
        if response["status"] == "OK":
            print(f"{Colors.GREEN}[AUTH] {response['msg']}{Colors.ENDC}")
            return True
        elif response["status"] == "OUTDATED":
            print(f"\n{Colors.RED}{Colors.BOLD}🚨 SERVER ALERT: {response['msg']}{Colors.ENDC}")
            print(f"{Colors.YELLOW} -> Recommendation: You MUST perform an Ingestion (Option 1) immediately to refresh your data.{Colors.ENDC}\n")
            return False
        else:
            print(f"{Colors.RED}[AUTH FAILED] {response['msg']}{Colors.ENDC}")
            return False

    def process_ingestion(self, json_file_path: str, server_node) -> None:
        auth = server_node.authenticate(self.api_key)
        if auth["status"] == "ERROR":
            print("Authentication failed.")
            return

        try:
            with open(json_file_path, 'r') as f:
                raw_data = json.load(f)
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File {json_file_path} not found.{Colors.ENDC}")
            return

        print(f"🔒 [CLIENT] Processing {len(raw_data)} records for ingestion...")
        data_to_finalize = []

        for record in raw_data:
            email = record['email']
            blinded_val = OPRFMath.mod_pow(OPRFMath.map_string_to_group(email), self._blinding_factor)
            signed_val, key_v = server_node.sign_blinded_request(blinded_val)
            inv_r = OPRFMath.mod_inverse(self._blinding_factor)
            final_val_int = OPRFMath.mod_pow(signed_val, inv_r)
            final_sig = hex(final_val_int)[2:]

            data_to_finalize.append({
                "signature": final_sig,
                "risk": record['risk'],
                "role": record['role'],
                "key_version": key_v
            })

        # Send API KEY so server updates our version
        server_node.register_incident_batch(self.api_key, data_to_finalize)
        print(f"{Colors.GREEN}✅ Ingestion complete. Sync status updated.{Colors.ENDC}")


    def process_verification(self, json_file_path: str, server_node):
        is_healthy = self._check_server_health(server_node)
        
        if not is_healthy:
            choice = input(f"{Colors.RED}Do you want to proceed with verification anyway? (Results might be invalid) [y/n]: {Colors.ENDC}")
            if choice.lower() != 'y':
                return

        try:
            with open(json_file_path, 'r') as f:
                applicants = json.load(f)
        except FileNotFoundError:
            print(f"{Colors.RED}Error: File {json_file_path} not found.{Colors.ENDC}")
            return

        print(f"🕵️  [CLIENT] Verifying {len(applicants)} new applicants...")
        lookup_map = {} 
        signatures_to_check = []

        for app in applicants:
            email = app['email']
            blinded_val = OPRFMath.mod_pow(OPRFMath.map_string_to_group(email), self._blinding_factor)
            signed_val, _ = server_node.sign_blinded_request(blinded_val)
            inv_r = OPRFMath.mod_inverse(self._blinding_factor)
            final_sig = hex(OPRFMath.mod_pow(signed_val, inv_r))[2:]
            
            signatures_to_check.append(final_sig)
            lookup_map[final_sig] = app 

        results = server_node.check_status_batch(signatures_to_check)

        print(f"\n{Colors.HEADER}--- ANALYSIS REPORT ---{Colors.ENDC}")
        for sig, res in results.items():
            app_info = lookup_map[sig]
            if res['status'] == "FOUND":
                data = res['data']
                color = Colors.RED if data['role'] == "PERPETRATOR" else Colors.YELLOW
                action = "BLOCK" if data['role'] == "PERPETRATOR" else "VERIFY ID"
                print(f"{color}[ALERT] Applicant {app_info['id']} ({app_info['email']}){Colors.ENDC}")
                print(f"    Type: {data['risk']} | Role: {data['role']}")
            else:
                print(f"{Colors.GREEN}[PASS]  Applicant {app_info['id']} ({app_info['email']}) - CLEAN{Colors.ENDC}")