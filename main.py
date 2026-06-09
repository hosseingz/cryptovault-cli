from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import getpass
import base64
import json
import sys
import os



class SecureBackupManager:
    def __init__(self, filepath="passwords.crp"):
        self.filepath = filepath
        self.data = {}  # Holds the unencrypted data strictly in RAM

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a secure 32-byte Fernet key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP recommended iterations for SHA-256
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def load_file(self, password: str) -> bool:
        """
        Reads the encrypted file, extracts the salt, decrypts the content into RAM.
        Returns True if successful, False if password is wrong or file is corrupted.
        """
        if not os.path.exists(self.filepath):
            # If file doesn't exist, treat it as an empty database ready to be saved
            self.data = {}
            return True

        try:
            with open(self.filepath, 'rb') as file:
                payload = file.read()

            if len(payload) < 16:
                return False

            # Extract the 16-byte salt and the ciphertext
            salt = payload[:16]
            ciphertext = payload[16:]

            # Derive the key using the extracted salt and provided password
            key = self._derive_key(password, salt)
            fernet = Fernet(key)

            # Decrypt and parse JSON directly into memory
            decrypted_bytes = fernet.decrypt(ciphertext)
            self.data = json.loads(decrypted_bytes.decode('utf-8'))
            return True
        except Exception:
            # Decryption failed (Invalid Token / Wrong Password)
            return False

    def save_file(self, password: str):
        """Encrypts the current in-memory dictionary and saves it to disk."""
        # Convert the RAM dictionary back to a structured JSON string
        json_bytes = json.dumps(self.data, indent=4).encode('utf-8')

        # Generate a fresh random salt for every single save operation (Salt Rotation)
        salt = os.urandom(16)

        # Derive a new key with the new salt
        key = self._derive_key(password, salt)
        fernet = Fernet(key)

        # Encrypt the data
        ciphertext = fernet.encrypt(json_bytes)

        # Combine salt and ciphertext into one binary payload [16 bytes Salt][Ciphertext]
        payload = salt + ciphertext

        with open(self.filepath, 'wb') as file:
            file.write(payload)

    def set_value(self, keys: list, value):
        """
        Sets a value inside a nested dictionary dynamically using a list of keys.
        Example: keys=['cloud', 'github', 'token'] -> sets self.data['cloud']['github']['token'] = value
        """
        current = self.data
        for key in keys[:-1]:
            if key not in current or not isinstance(current[key], dict):
                current[key] = {}
            current = current[key]
        current[keys[-1]] = value

    def get_value(self, keys: list):
        """
        Retrieves a value from a nested dictionary path.
        Returns None if the path or key does not exist.
        """
        current = self.data
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
        return current

    def remove_value(self, keys: list) -> bool:
        """
        Removes a target key or sub-tree dynamically using its precise path list.
        Returns True if deleted successfully, False if path resolution fails.
        """
        if not keys:
            return False
            
        current = self.data
        for key in keys[:-1]:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return False
                
        if isinstance(current, dict) and keys[-1] in current:
            del current[keys[-1]]
            return True
        return False

    def get_all_data(self) -> dict:
        """Returns the entire dictionary currently held in RAM."""
        return self.data
    

class SecureBackupCLI:
    def __init__(self, manager: SecureBackupManager):
        self.manager = manager
        self.current_path = []  # Tracks the current position in the nested dict
        self.master_password = ""

    def _clear_screen(self):
        """Clears the terminal screen for security."""
        os.system('cls' if os.name == 'nt' else 'clear')

    def _get_current_node(self):
        """Returns the dictionary node at the current path."""
        if not self.current_path:
            return self.manager.get_all_data()
        return self.manager.get_value(self.current_path)

    def _print_prompt(self):
        """Generates a dynamic prompt based on the current path."""
        path_str = "/" + "/".join(self.current_path)
        print(f"\n[Vault:{path_str}]🔑 ", end="")

    def _get_sorted_keys(self, node: dict) -> list:
        """
        Sorts keys within a dictionary node. 
        Directories (nested dicts) come first, then sorted alphabetically.
        """
        return sorted(node.keys(), key=lambda k: (0 if isinstance(node[k], dict) else 1, k.lower()))

    def _resolve_key(self, target: str) -> str:
        """
        Resolves a numeric index input back to its actual string key.
        Implements 'Exact Match Priority' to prevent dangerous overwrites if a key is named '1'.
        """
        node = self._get_current_node()
        if not isinstance(node, dict):
            return target

        # 1. Exact Match Priority: If the key literally exists, return it immediately.
        if target in node:
            return target

        # 2. Index Resolution: If input is a number, map it to the sorted list.
        if target.isdigit():
            idx = int(target)
            sorted_keys = self._get_sorted_keys(node)
            # Ensure the provided index is within valid bounds (1-based index)
            if 1 <= idx <= len(sorted_keys):
                return sorted_keys[idx - 1]

        # 3. Fallback: Return raw target (will naturally fail later if invalid)
        return target

    def authenticate(self) -> bool:
        """Handles the initial login/decryption phase."""
        print("=== Secure Backup Manager CLI ===")
        password = getpass.getpass("Enter Master Password: ")
        
        if self.manager.load_file(password):
            self.master_password = password
            print("[-] Access Granted. Vault loaded into RAM.")
            return True
        else:
            print("[!] Access Denied. Wrong password or corrupted file.")
            return False

    def cmd_ls(self):
        """Lists keys at the current level or prints the value if it's a leaf."""
        node = self._get_current_node()
        if isinstance(node, dict):
            if not node:
                print("  (empty directory)")
                return
            
            print("\nAvailable Keys:")
            sorted_keys = self._get_sorted_keys(node)
            for idx, key in enumerate(sorted_keys, start=1):
                val = node[key]
                type_indicator = "[DIR]" if isinstance(val, dict) else "[VAL]"
                print(f"  {idx}. {type_indicator} {key}")
        else:
            print(f"\nValue: {node}")

    def cmd_cd(self, target: str):
        """Navigates inside the nested structure."""
        if target == "..":
            if self.current_path:
                self.current_path.pop()
            return

        target_key = self._resolve_key(target)

        node = self._get_current_node()
        if isinstance(node, dict) and target_key in node:
            if isinstance(node[target_key], dict):
                self.current_path.append(target_key)
            else:
                print(f"[!] '{target_key}' is a value, not a directory. Cannot cd into it.")
        else:
            print(f"[!] Key or Index '{target}' not found.")

    def cmd_mkdir(self, key: str):
        """Creates a new empty dictionary (directory) at the current path."""
        node = self._get_current_node()
        if not isinstance(node, dict):
            print("[!] Cannot create a directory inside a value node.")
            return

        # We DO NOT use _resolve_key here. 
        # If the user types 'mkdir 1', they explicitly want a directory named '1'.
        if key in node:
            print(f"[!] Key '{key}' already exists.")
            return

        # Use the manager's set_value to safely implant an empty dictionary
        full_path = self.current_path + [key]
        self.manager.set_value(full_path, {})
        print(f"[-] Created directory '{key}'. You can now 'cd' into it.")

    def cmd_get(self, key: str):
        """Retrieves and displays a specific value without changing paths."""
        target_key = self._resolve_key(key)
        
        node = self._get_current_node()
        if isinstance(node, dict) and target_key in node:
            print(f"\n{target_key} -> {node[target_key]}")
        else:
            print(f"[!] Key or Index '{key}' not found here.")

    def cmd_set(self, key: str, value: str):
        """Sets or updates a value at the current path."""
        node = self._get_current_node()
        if not isinstance(node, dict):
            print("[!] Cannot set a key-value pair inside a value node.")
            return
            
        # Resolve index. If index exists, update it. If not, treat as a new literal key name.
        target_key = self._resolve_key(key)

        full_path = self.current_path + [target_key]
        self.manager.set_value(full_path, value)
        print(f"[-] Successfully set '{target_key}'. Remember to 'save'.")

    def cmd_rm(self, target_key: str):
        """
        Removes a key or an entire directory from the current node level.
        Requires literal matches only (forbids index numeric mapping) and enforces target-aware confirmation terms.
        """
        node = self._get_current_node()
        if not isinstance(node, dict):
            print("[!] Cannot execute destruction commands on a leaf value node.")
            return

        # Explicit Security Friction: Strictly bypass index resolution. 
        # Even if target_key is a valid integer string, treat it strictly as a literal key name.
        if target_key not in node:
            print(f"[!] Key '{target_key}' not found. Note: 'rm' strictly requires literal key names, not numeric IDs.")
            return

        target_node = node[target_key]
        
        # Scenario A: Non-empty Directory (Demands Recursive Deep-Purge Agreement)
        if isinstance(target_node, dict) and len(target_node) > 0:
            item_count = len(target_node)
            print(f"[⚠️ WARNING] '{target_key}' is a non-empty directory containing {item_count} active item(s).")
            print("[!] This action will recursively delete ALL nested keys inside this tree structure.")
            confirm = input("--> To proceed, type 'DELETE_ALL' exactly: ").strip()
            if confirm != "DELETE_ALL":
                print("[-] Aborted. No structures were harmed.")
                return

        # Scenario B: Leaf Node (Value) or Empty Directory (Requires Simple Affirmation)
        else:
            node_type = "empty directory" if isinstance(target_node, dict) else "value node"
            print(f"[⚠️ WARNING] You are about to delete the {node_type} named '{target_key}'.")
            confirm = input("--> To proceed, type 'YES' exactly: ").strip()
            if confirm != "YES":
                print("[-] Aborted. Deletion cancelled.")
                return

        # Execute dynamic structural detachment via manager
        full_path = self.current_path + [target_key]
        if self.manager.remove_value(full_path):
            print(f"[+] Successfully purged '{target_key}' from active RAM state. Remember to 'save'.")
        else:
            print("[!] Critical Failure: Failed to remove node structure from path state.")

    def cmd_help(self):
        """Prints available commands."""
        print("\nCommands:")
        print("  ls          - List keys (Sorted, DIRs first)")
        print("  cd <key/id> - Move into a key (use 'cd ..' to go back)")
        print("  mkdir <key> - Create a new empty nested directory")
        print("  get <key/id>- View the value of a specific key")
        print("  set <k> <v> - Set a value at the current path")
        print("  rm <key>    - Delete a key or directory (Requires precise literal name)")
        print("  save        - Encrypt and commit changes to disk")
        print("  clear       - Clear the terminal screen")
        print("  exit        - Exit the manager")

    def run(self):
        """Main execution loop for the CLI interaction."""
        if not self.authenticate():
            return

        self.cmd_help()

        while True:
            try:
                self._print_prompt()
                user_input = input().strip().split(maxsplit=2)
                if not user_input:
                    continue

                cmd = user_input[0].lower()

                if cmd == "exit":
                    print("Exiting. Unsaved changes in RAM will be lost.")
                    break
                elif cmd == "ls":
                    self.cmd_ls()
                elif cmd == "help":
                    self.cmd_help()
                elif cmd == "clear":
                    self._clear_screen()
                elif cmd == "cd":
                    if len(user_input) < 2:
                        print("[!] Usage: cd <key_name or id> or cd ..")
                    else:
                        self.cmd_cd(user_input[1])
                elif cmd == "mkdir":
                    if len(user_input) < 2:
                        print("[!] Usage: mkdir <key_name>")
                    else:
                        self.cmd_mkdir(user_input[1])
                elif cmd == "get":
                    if len(user_input) < 2:
                        print("[!] Usage: get <key_name or id>")
                    else:
                        self.cmd_get(user_input[1])
                elif cmd == "set":
                    if len(user_input) < 3:
                        print("[!] Usage: set <key_name or id> <value>")
                    else:
                        self.cmd_set(user_input[1], user_input[2])
                elif cmd == "rm":
                    if len(user_input) < 2:
                        print("[!] Usage: rm <exact_key_name>")
                    else:
                        self.cmd_rm(user_input[1])
                elif cmd == "save":
                    self.manager.save_file(self.master_password)
                    print("[+] Database encrypted and safely written to disk.")
                else:
                    print("[!] Unknown command. Type 'help' for available options.")

            except (KeyboardInterrupt, EOFError):
                print("\nSession interrupted. Exiting safely.")
                break


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("[!] Error: Missing database name argument.")
        print("[-] Usage: python main.py <database_name>")
        sys.exit(1)

    target_file = sys.argv[1].strip()

    if not target_file.endswith(".crp"):
        target_file += ".crp"

    manager = SecureBackupManager(target_file)
    cli = SecureBackupCLI(manager)
    cli.run()