# CryptoVault CLI

CryptoVault CLI is a lightweight, local-first secure backup and credential manager. It allows you to store heavily nested data structures inside an encrypted file while interacting with them seamlessly through a terminal interface that mimics a standard Linux shell (`cd`, `ls`, `mkdir`, `rm`).

Data is decrypted strictly into RAM during runtime and is never leaked to the disk in plaintext.

---

## 🔒 Security Architecture

* **Key Derivation:** PBKDF2HMAC utilizing SHA-256 with 600,000 iterations (OWASP compliant) to derive a secure 32-byte key from your master password.
* **Encryption:** Authenticated symmetric encryption via AES-128 in CBC mode with a SHA-256 HMAC (Fernet specification).
* **Salt Rotation:** A fresh, random 16-byte salt (`os.urandom`) is generated on every single save operation to mitigate cryptographic wear and replay attacks.
* **Destructive Operation Friction:** Structural deletions enforce explicit validation mechanisms based on node depth and type to prevent accidental data loss.

---

## 🛠️ Requirements & Installation

To minimize the external attack surface and ensure cross-platform portability, CryptoVault relies strictly on Python's built-in libraries combined with a single, industry-standard cryptographic library.

### Prerequisites
- Python 3.7+

### Installation & Setup

It is highly recommended to install the dependencies inside an isolated virtual environment (`venv`) to prevent conflicts with global system packages.

1. Clone the repository to your local machine:

```bash
git clone https://github.com/hosseingz/cryptovault-cli.git
cd cryptovault-cli

```

2. Create and activate a virtual environment:

* **Linux / macOS:**

```bash
python3 -m venv venv
source venv/bin/activate

```

* **Windows (Command Prompt):**

```cmd
python -m venv venv
venv\Scripts\activate.bat

```

* **Windows (PowerShell):**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1

```

3. Install the required external core dependency:

```bash
pip install --upgrade pip
pip install -r requirements.txt

```

---

## 🚀 Usage

To run the application, execute the main script while providing the database filename as an argument.

> 💡 **Note:** You do not need to type the extension manually. The CLI automatically appends `.crp` if it is omitted.

```bash
# Ensure your virtual environment is active before running
python main.py my_vault

```

If the specified file (e.g., `my_vault.crp`) does not exist, the CLI will initialize a clean, empty database architecture in memory, ready to be populated and committed to disk.

### CLI Command Reference

Once authenticated, you can traverse and manipulate your data tree using the following commands:

| Command | Syntax | Description |
| --- | --- | --- |
| `ls` | `ls` | Lists indexed directories `[DIR]` and values `[VAL]` at the current path level. |
| `cd` | `cd <key>` or `cd <index>` or `cd ..` | Navigates into a directory using its exact key name or its numeric index. Use `..` to return to the parent directory. |
| `mkdir` | `mkdir <key>` | Creates a new empty nested directory (dictionary) at the current level. **Always processes input as a literal name, ignoring index numbers.** |
| `set` | `set <key/index> <value>` | Assigns a string value to a key or updates an existing node via its index number. |
| `get` | `get <key>` or `get <index>` | Displays the value of a specific node using its exact name or numeric index without changing your path. |
| `rm` | `rm <exact_key>` | Detaches a key or an entire directory from the active RAM state. **Enforces security confirmation and bypasses numeric index translation.** |
| `save` | `save` | Rotates the salt, re-encrypts the RAM data, and commits changes to disk. |
| `clear` | `clear` | Clears the screen to prevent optical leaking of sensitive terminal logs. |
| `exit` | `exit` | Terminates the session. Unsaved changes in RAM will be destroyed. |

> ⚠️ **Exact Match Priority Rule:** If you pass an integer (e.g., `get 1`) to a command, the system will first look for a key literally named `"1"`. If no such literal key exists, it will fall back to resolving it as the 1st item from the last sorted `ls` output.

> 🔴 **CRITICAL EXCEPTIONS:** The `mkdir` and `rm` commands explicitly bypass index resolution. For example, `rm 1` will search exclusively for a key literally named `"1"` and will never map to the first item of an `ls` block.

---

## 💡 Example Session

```text
$ python main.py production_secrets

=== Secure Backup Manager CLI ===
Enter Master Password: 
[-] Access Granted. Vault loaded into RAM.

[Vault:/]🔑 mkdir infrastructure
[-] Created directory 'infrastructure'. You can now 'cd' into it.

[Vault:/]🔑 cd 1

[Vault:/infrastructure]🔑 set prod_db_host 10.0.0.5
[-] Successfully set 'prod_db_host'. Remember to 'save'.

[Vault:/infrastructure]🔑 set secondary_db 10.0.0.6
[-] Successfully set 'secondary_db'. Remember to 'save'.

[Vault:/infrastructure]🔑 ls

Available Keys:
  1. [VAL] prod_db_host
  2. [VAL] secondary_db

[Vault:/infrastructure]🔑 rm secondary_db
[⚠️ WARNING] You are about to delete the value node named 'secondary_db'.
--> To proceed, type 'YES' exactly: YES
[+] Successfully purged 'secondary_db' from active RAM state. Remember to 'save'.

[Vault:/infrastructure]🔑 cd ..

[Vault:/]🔑 rm infrastructure
[⚠️ WARNING] 'infrastructure' is a non-empty directory containing 1 active item(s).
[!] This action will recursively delete ALL nested keys inside this tree structure.
--> To proceed, type 'DELETE_ALL' exactly: DELETE_ALL
[+] Successfully purged 'infrastructure' from active RAM state. Remember to 'save'.

[Vault:/]🔑 save
[+] Database encrypted and safely written to disk.

[Vault:/]🔑 exit

```

---

## ⚠️ Important Security Disclaimers

1. **Memory Safety:** Plaintext structures are held in Python's memory heap during the active session. Ensure your host environment is fully secured against unauthorized local inspection, debugging, or memory dumping processes.
2. **Zero-Knowledge Recovery:** This architecture features a strict zero-knowledge model. There is no back-door, alternative recovery key, or bypass mechanism. If the master password is lost or forgotten, the underlying data payload cannot be recovered.
3. **Data Loss Mitigation (Friction Protocol):** Destructive functions (`rm`) utilize varying levels of structural confirmation:
* **Leaf/Empty Directories:** Require a literal `YES` confirmation.
* **Populated Sub-trees:** Require a recursive deep-purge validation string (`DELETE_ALL`) to deter unexpected downstream node termination.