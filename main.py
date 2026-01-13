"""
SilentMatch Protocol - Consortium Edition (Prototype v0.2)
Copyright (c) 2026 - Éloïc Côté -
Licensed under MIT License.
"""

import hashlib
import secrets
import time
import logging
import concurrent.futures
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from enum import Enum

# --- CONFIGURATION & UTILS ---

# Simulates a secure shared key for the consortium members (in prod: OPRF protocol)
CONSORTIUM_SALT = "e8f32a...SHARED_SECRET"

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')
logger = logging.getLogger("SilentMatchCore")

class Colors:
    """ANSI Colors for professional terminal output"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# --- 1. BUSINESS DEFINITIONS (ENUMS) ---

class RiskType(Enum):
    """What is the nature of the incident?"""
    CREDIT_DEFAULT = "CREDIT_DEFAULT" # Non-payment
    IDENTITY_THEFT = "IDENTITY_THEFT" # Stolen credentials
    MONEY_LAUNDERING = "MONEY_LAUNDERING" # Severe crime
    SYNTHETIC_ID = "SYNTHETIC_ID" # Fake profile

class ActorRole(Enum):
    """What role did this email/identity play?"""
    PERPETRATOR = "PERPETRATOR" # The criminal
    VICTIM = "VICTIM" # The innocent owner of the data
    SUSPECT = "SUSPECT" # Unconfirmed

# --- 2. DATA STRUCTURES ---

@dataclass
class ReputationScore:
    """
    The 'Credit Score' of a hash.
    Aggregates reports from multiple banks to reduce false positives.
    """
    hash_id: str
    total_reports: int = 0
    confirmed_fraud_count: int = 0
    victim_reports_count: int = 0
    
    @property
    def current_verdict(self) -> str:
        """Determines the recommended action based on history."""
        if self.victim_reports_count > 0:
            return "VICTIM_PROTECTION_MODE" # Do not block, but verify ID
        if self.confirmed_fraud_count >= 1:
            return "HIGH_RISK_BLOCK" # Confirmed bad actor
        return "NO_DATA"

@dataclass
class BankCustomer:
    """Clear-text data (Internal to the Bank only)"""
    internal_id: str # e.g., "APP-2026-001"
    email: str
    sin_last4: str

# --- 3. CLIENT-SIDE SECURITY (The Bank's Server) ---

class ClientSecurityEngine:
    """
    Handles ETL (Extract, Transform, Load) and Hashing locally.
    Data never leaves this class in clear text.
    """
    
    @staticmethod
    def normalize(text: str) -> str:
        return text.strip().lower().replace(" ", "").replace("-", "")

    @staticmethod
    def hash_record(text: str) -> str:
        """
        One-way encryption using SHA-256 + Salt.
        Optimized for speed.
        """
        clean = ClientSecurityEngine.normalize(text)
        payload = clean + CONSORTIUM_SALT
        return hashlib.sha256(payload.encode()).hexdigest()

    @staticmethod
    def batch_process(customers: List[BankCustomer]) -> Dict[str, str]:
        """
        Uses Multi-threading to process thousands of records/sec.
        Returns: { Internal_ID : Secure_Hash }
        """
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            # Map internal ID to the future result
            future_to_id = {
                executor.submit(ClientSecurityEngine.hash_record, c.email): c.internal_id 
                for c in customers
            }
            
            for future in concurrent.futures.as_completed(future_to_id):
                internal_id = future_to_id[future]
                secure_hash = future.result()
                results[internal_id] = secure_hash
                
        return results

# --- 4. SERVER-SIDE LOGIC (Your API) ---

class SilentMatchConsortium:
    """
    The Centralized Ledger. 
    It only knows Hash Strings and Reputation Scores. Zero PII.
    """
    def __init__(self):
        self._ledger: Dict[str, ReputationScore] = {}
        self._risk_metadata: Dict[str, RiskType] = {} # Hash -> Last Risk Type

    def contribute_report(self, bank_name: str, email_hash: str, risk: RiskType, role: ActorRole):
        """A bank reports a historical incident."""
        if email_hash not in self._ledger:
            self._ledger[email_hash] = ReputationScore(hash_id=email_hash)
        
        # Update Statistics
        score = self._ledger[email_hash]
        score.total_reports += 1
        
        if role == ActorRole.PERPETRATOR:
            score.confirmed_fraud_count += 1
        elif role == ActorRole.VICTIM:
            score.victim_reports_count += 1
            
        # Store metadata
        self._risk_metadata[email_hash] = risk
        
        logger.info(f"DB Update: [{bank_name}] flagged hash {email_hash[:8]}... as {role.value}")

    def check_applicants(self, queries: Dict[str, str]) -> Dict[str, dict]:
        """
        Checks a batch of hashes against the ledger.
        Returns detailed verdicts.
        """
        start_t = time.perf_counter()
        matches = {}
        
        for internal_id, secure_hash in queries.items():
            if secure_hash in self._ledger:
                score = self._ledger[secure_hash]
                risk = self._risk_metadata.get(secure_hash, RiskType.CREDIT_DEFAULT)
                
                matches[internal_id] = {
                    "verdict": score.current_verdict,
                    "risk_type": risk.name,
                    "reports": score.total_reports
                }
        
        end_t = time.perf_counter()
        logger.info(f"Processed {len(queries)} queries in {(end_t - start_t)*1000:.2f}ms")
        return matches

# --- 5. DEMO EXECUTION ---

def run_demo():
    print(f"{Colors.HEADER}{'='*60}")
    print(f" 🚀 SILENTMATCH - CONSORTIUM PROTOCOL (v0.2)")
    print(f" Privacy-Preserving Fraud Detection | Law 25 Compliant")
    print(f"{'='*60}{Colors.ENDC}\n")

    # --- SETUP ---
    api_server = SilentMatchConsortium()
    
    print(f"{Colors.BOLD}STEP 1: Historic Data Loading (Consortium Knowledge){Colors.ENDC}")
    # Scenario: RBC and TD previously reported incidents
    
    # 1. A real criminal (First Party Fraud)
    criminal_email = "bad.actor@gmail.com"
    criminal_hash = ClientSecurityEngine.hash_record(criminal_email)
    api_server.contribute_report("RBC", criminal_hash, RiskType.MONEY_LAUNDERING, ActorRole.PERPETRATOR)
    
    # 2. A victim of identity theft (Third Party Fraud)
    victim_email = "alice.smith@yahoo.ca"
    victim_hash = ClientSecurityEngine.hash_record(victim_email)
    api_server.contribute_report("TD Bank", victim_hash, RiskType.IDENTITY_THEFT, ActorRole.VICTIM)
    
    print("-" * 60)

    # --- LIVE REQUEST ---
    print(f"\n{Colors.BOLD}STEP 2: New Application Batch (National Bank){Colors.ENDC}")
    # National Bank receives 3 new loan applications
    
    applicants = [
        BankCustomer("APP-001", "john.doe@gmail.com", "1234"), # Clean user
        BankCustomer("APP-002", "BAD.ACTOR@gmail.com", "9999"), # Criminal (Bad casing)
        BankCustomer("APP-003", "alice.smith@yahoo.ca", "5555") # Victim
    ]

    print(f" -> Processing {len(applicants)} applicants via Local Security Engine...")
    
    # 1. Local Hashing (Multi-threaded)
    secure_batch = ClientSecurityEngine.batch_process(applicants)
    
    # 2. API Call (Blind Query)
    print(f" -> Sending blind hashes to SilentMatch API...")
    results = api_server.check_applicants(secure_batch)

    # --- REPORTING ---
    print(f"\n{Colors.HEADER}STEP 3: FINAL AUDIT REPORT{Colors.ENDC}")
    
    for app in applicants:
        uid = app.internal_id
        
        if uid in results:
            data = results[uid]
            verdict = data["verdict"]
            
            if verdict == "HIGH_RISK_BLOCK":
                print(f"{Colors.RED}[BLOCK] Applicant {uid} ({app.email}){Colors.ENDC}")
                print(f" Reason: {data['risk_type']} (Confirmed Perpetrator)")
                print(f" Action: Auto-Decline Loan.")
                
            elif verdict == "VICTIM_PROTECTION_MODE":
                print(f"{Colors.YELLOW}[ALERT] Applicant {uid} ({app.email}){Colors.ENDC}")
                print(f" Reason: {data['risk_type']} (Known Victim)")
                print(f" Action: MANUAL REVIEW REQUIRED (Verify ID). Do not block.")
        
        else:
            print(f"{Colors.GREEN}[PASS] Applicant {uid} ({app.email}){Colors.ENDC}")
            print(f" Status: No adverse history found.")
        
        print("-" * 30)

if __name__ == "__main__":
    run_demo()