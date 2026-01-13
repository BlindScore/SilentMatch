"""
config.py
Shared constants.
"""
from enum import Enum
import os

# Create data directories
if not os.path.exists("data"):
    os.makedirs("data")
    
# Create a specific folder for ledger versions
if not os.path.exists("data/ledgers"):
    os.makedirs("data/ledgers")

# File Paths
LEDGER_DIR = "data/ledgers" 

KEYS_FILE = "data/server_keys.json"
CLIENTS_FILE = "data/authorized_clients.json"
INPUT_FRAUD_FILE = "data/input_fraudsters.json"
INPUT_CHECK_FILE = "data/input_verification.json"

# Crypto Constants
PRIME_MODULUS = int("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF".replace("\n", ""), 16)

class RiskType(Enum):
    CREDIT_DEFAULT = "CREDIT_DEFAULT"
    IDENTITY_THEFT = "IDENTITY_THEFT"
    MONEY_LAUNDERING = "MONEY_LAUNDERING"

class ActorRole(Enum):
    PERPETRATOR = "PERPETRATOR"
    VICTIM = "VICTIM"

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'