from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
import getpass
import base64
import json
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
                print(" (empty directory)")
                return
            print("\nAvailable Keys:")
            for key, val in node.items():
                type_indicator = "[DIR]" if isinstance(val, dict) else "[VAL]"
                print(f"  {type_indicator} {key}")
        else:
            print(f"\nValue: {node}")

    def cmd_cd(self, target: str):
        """Navigates inside the nested structure."""
        if target == "..":
            if self.current_path:
                self.current_path.pop()
            return

        node = self._get_current_node()
        if isinstance(node, dict) and target in node:
            if isinstance(node[target], dict):
                self.current_path.append(target)
            else:
                print(f"[!] '{target}' is a value, not a directory. Cannot cd into it.")
        else:
            print(f"[!] Key '{target}' not found.")

    def cmd_mkdir(self, key: str):
        """Creates a new empty dictionary (directory) at the current path."""
        node = self._get_current_node()
        if not isinstance(node, dict):
            print("[!] Cannot create a directory inside a value node.")
            return

        if key in node:
            print(f"[!] Key '{key}' already exists.")
            return

        # Use the manager's set_value to safely implant an empty dictionary
        full_path = self.current_path + [key]
        self.manager.set_value(full_path, {})
        print(f"[-] Created directory '{key}'. You can now 'cd' into it.")

    def cmd_get(self, key: str):
        """Retrieves and displays a specific value without changing paths."""
        node = self._get_current_node()
        if isinstance(node, dict) and key in node:
            print(f"\n{key} -> {node[key]}")
        else:
            print(f"[!] Key '{key}' not found here.")

    def cmd_set(self, key: str, value: str):
        """Sets or updates a value at the current path."""
        node = self._get_current_node()
        if not isinstance(node, dict):
            print("[!] Cannot set a key-value pair inside a value node.")
            return
            
        full_path = self.current_path + [key]
        self.manager.set_value(full_path, value)
        print(f"[-] Successfully set '{key}'. Remember to 'save'.")

    def cmd_help(self):
        """Prints available commands."""
        print("\nCommands:")
        print("  ls          - List keys at current level")
        print("  cd <key>    - Move into a key (use 'cd ..' to go back)")
        print("  mkdir <key> - Create a new empty nested directory")
        print("  get <key>   - View the value of a specific key")
        print("  set <k> <v> - Set a value at the current path")
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
                        print("[!] Usage: cd <key_name> or cd ..")
                    else:
                        self.cmd_cd(user_input[1])
                elif cmd == "mkdir":
                    if len(user_input) < 2:
                        print("[!] Usage: mkdir <key_name>")
                    else:
                        self.cmd_mkdir(user_input[1])
                elif cmd == "get":
                    if len(user_input) < 2:
                        print("[!] Usage: get <key_name>")
                    else:
                        self.cmd_get(user_input[1])
                elif cmd == "set":
                    if len(user_input) < 3:
                        print("[!] Usage: set <key_name> <value>")
                    else:
                        self.cmd_set(user_input[1], user_input[2])
                elif cmd == "save":
                    self.manager.save_file(self.master_password)
                    print("[+] Database encrypted and safely written to disk.")
                else:
                    print("[!] Unknown command. Type 'help' for available options.")

            except (KeyboardInterrupt, EOFError):
                print("\nSession interrupted. Exiting safely.")
                break



if __name__ == "__main__":
    manager = SecureBackupManager("passwords.crp")
    cli = SecureBackupCLI(manager)
    cli.run()