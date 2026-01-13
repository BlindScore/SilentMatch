"""
main.py
The Orchestrator / Demo Script with CLI.
"""
import sys
import json
import os
import shutil
from config import Colors, INPUT_FRAUD_FILE, INPUT_CHECK_FILE, LEDGER_DIR, KEYS_FILE, CLIENTS_FILE
from server import SilentMatchNode
from client import BankSecurityModule

def create_dummy_data():
    """Generates dummy JSON files for the demo manually."""
    print(f"\n{Colors.BLUE}[GENERATOR] Creating sample datasets...{Colors.ENDC}")
    
    data_fraud = [
        {
            "email": "badguy@gmail.com", 
            "phone": "514-555-0000",
            "sin": "123 456 789",
            "risk": "MONEY_LAUNDERING", 
            "role": "PERPETRATOR"
        },
        {
            "sin": "999-999-999",
            "risk": "IDENTITY_THEFT", 
            "role": "VICTIM"
        }
    ]
    with open(INPUT_FRAUD_FILE, 'w') as f:
        json.dump(data_fraud, f, indent=4)
        
    data_check = [
        {
            "id": "APP-001 (Clean)", 
            "email": "innocent@gmail.com", 
            "phone": "450-111-1111",
            "sin": "111 111 111"
        },
        {
            "id": "APP-002 (Fraudeur connu)", 
            "email": "badguy@gmail.com",
            "phone": "514-555-9999",
            "sin": "000 000 000"
        },
        {
            "id": "APP-003 (NAS Volé)", 
            "email": "nouveau.mail@hotmail.com",
            "phone": "418-222-2222",
            "sin": "999999999"
        }
    ]
    with open(INPUT_CHECK_FILE, 'w') as f:
        json.dump(data_check, f, indent=4)
    print(f"{Colors.GREEN}✅ Dummy data generated.{Colors.ENDC}")

def reset_demo_environment():
    """Cleans all data including the ledgers folder AND clients."""
    print(f"\n{Colors.RED}{Colors.BOLD}⚠️  WARNING: FACTORY RESET INITIATED ⚠️{Colors.ENDC}")
    print("This will delete ALL Ledger Versions, Keys, CLIENTS, and Input Files.")
    confirm = input("Are you sure? (y/n): ")
    
    if confirm.lower() != 'y':
        return False

    files_to_clean = [KEYS_FILE, CLIENTS_FILE, INPUT_FRAUD_FILE, INPUT_CHECK_FILE]
    for file_path in files_to_clean:
        if os.path.exists(file_path):
            os.remove(file_path)

    if os.path.exists(LEDGER_DIR):
        shutil.rmtree(LEDGER_DIR)
        os.makedirs(LEDGER_DIR)

    print(f"{Colors.GREEN}System cleaned successfully.{Colors.ENDC}")
    return True

def handle_login(server):
    """Affiche un menu pour choisir un client existant OU se déconnecter."""
    clients_list = server.client_mgr.get_all_clients()
    
    print(f"\n{Colors.BOLD}--- SELECT PROFILE ---{Colors.ENDC}")
    
    if clients_list:
        for idx, (name, key) in enumerate(clients_list):
            print(f"{idx + 1}. {name} (Key: {key[:6]}...)")
    else:
        print("(No clients registered yet)")

    print("0. ❌ Logout / Cancel")
    
    try:
        selection = int(input("\nSelect User ID: "))
        
        if selection == 0:
            print(f"{Colors.YELLOW}Logged out.{Colors.ENDC}")
            return None, "Guest"
            
        idx = selection - 1
        if 0 <= idx < len(clients_list):
            name, key = clients_list[idx]
            print(f"{Colors.GREEN}Successfully logged in as {name}{Colors.ENDC}")
            return key, name
        else:
            print("Invalid selection.")
            return None, "Guest"
            
    except ValueError:
        print("Invalid input.")
        return None, "Guest"

def main():
    print(f"{Colors.HEADER}{'='*50}")
    print(f"   SILENTMATCH V2 - CONSORTIUM MANAGER")
    print(f"{'='*50}{Colors.ENDC}")
    
    server = SilentMatchNode()
    current_api_key = None
    current_client_name = "Guest"
    
    while True:
        if current_api_key:
            status_color = Colors.GREEN
            status_text = f"LOGGED IN as {current_client_name}"
        else:
            status_color = Colors.RED
            status_text = "NO SESSION"

        print("\n" + "-"*30)
        print(f"STATUS: {status_color}{status_text}{Colors.ENDC} | SERVER: v{server.kms.current_version}")
        print("1. 🆕 REGISTER : Create new Bank Client")
        print("2. 👤 LOGIN : Switch Profile (or Logout)")
        print("3. 📥 INGESTION : Upload Fraudsters")
        print("4. 🔎 VERIFICATION : Check Applicants")
        print("5. 🔑 ADMIN : Rotate Server Key")
        print(f"6. 🧹 {Colors.RED}RESET : Factory Reset{Colors.ENDC}")
        print(f"7. 🎲 {Colors.BLUE}GENERATE : Dummy Data{Colors.ENDC}")
        print("8. ❌ Quit")
        
        choice = input(f"\nYour choice (1-8): ")
        
        if choice == "1":
            name = input("Enter Bank Name (e.g. RBC): ")
            key = server.client_mgr.create_api_key(name)
            current_api_key = key
            current_client_name = name
            print(f"{Colors.GREEN}Registered & Logged in. API Key: {key}{Colors.ENDC}")
            
        elif choice == "2":
            key, name = handle_login(server)
            current_api_key = key
            current_client_name = name

        elif choice == "3":
            if not current_api_key:
                print(f"{Colors.RED}Login required.{Colors.ENDC}")
                continue
            client = BankSecurityModule(current_api_key)
            client.process_ingestion(INPUT_FRAUD_FILE, server)
            
        elif choice == "4":
            if not current_api_key:
                print(f"{Colors.RED}Login required.{Colors.ENDC}")
                continue
            client = BankSecurityModule(current_api_key)
            client.process_verification(INPUT_CHECK_FILE, server)
            
        elif choice == "5":
            new_v = server.rotate_server()
            print(f"{Colors.YELLOW}System migrated to v{new_v}.json.{Colors.ENDC}")
            print(f"{Colors.RED}All v{new_v-1} data is now archived.{Colors.ENDC}")

        elif choice == "6":
            if reset_demo_environment():
                print(f"\n{Colors.BLUE}[SYSTEM] Rebooting Server Node...{Colors.ENDC}")
                server = SilentMatchNode()
                current_api_key = None
                current_client_name = "Guest"
                print("Server ready. Logged out.")
            
        elif choice == "7":
            create_dummy_data()
            
        elif choice == "8":
            sys.exit()

if __name__ == "__main__":
    main()