# CryptoVault CLI

CryptoVault CLI is a lightweight, local-first secure backup and credential manager. It allows you to store heavily nested data structures inside an encrypted file while interacting with them seamlessly through a terminal interface that mimics a standard Linux shell (`cd`, `ls`, `mkdir`).

Data is decrypted strictly into RAM during runtime and is never leaked to the disk in plaintext.

---

## 🔒 Security Architecture

- **Key Derivation:** PBKDF2HMAC utilizing SHA-256 with 600,000 iterations (OWASP compliant) to derive a secure 32-byte key from your master password.
- **Encryption:** Authenticated symmetric encryption via AES-128 in CBC mode with a SHA-256 HMAC (Fernet specification).
- **Salt Rotation:** A fresh, random 16-byte salt (`os.urandom`) is generated on every single save operation to mitigate cryptographic wear and replay attacks.

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
| `ls` | `ls` | Lists directories `[DIR]` and values `[VAL]` at the current path level. |
| `cd` | `cd <key>` or `cd ..` | Navigates into a directory key or goes back to the parent directory. |
| `mkdir` | `mkdir <key>` | Creates a new empty nested directory (dictionary) at the current level. |
| `set` | `set <key> <value>` | Assigns a string value to a key at the current level. |
| `get` | `get <key>` | Displays the value of a specific key without changing your path. |
| `save` | `save` | Rotates the salt, re-encrypts the RAM data, and commits changes to disk. |
| `clear` | `clear` | Clears the screen to prevent optical leaking of sensitive terminal logs. |
| `exit` | `exit` | Terminates the session. Unsaved changes in RAM will be destroyed. |

---

## 💡 Example Session

```text
$ python main.py production_secrets

=== Secure Backup Manager CLI ===
Enter Master Password: 
[-] Access Granted. Vault loaded into RAM.

[Vault:/]🔑 mkdir infrastructure
[-] Created directory 'infrastructure'. You can now 'cd' into it.

[Vault:/]🔑 cd infrastructure

[Vault:/infrastructure]🔑 set prod_db_host 10.0.0.5
[-] Successfully set 'prod_db_host'. Remember to 'save'.

[Vault:/infrastructure]🔑 ls
Available Keys:
  [VAL] prod_db_host

[Vault:/infrastructure]🔑 save
[+] Database encrypted and safely written to disk.

[Vault:/infrastructure]🔑 exit

```

---

## ⚠️ Important Security Disclaimers

1. **Memory Safety:** Plaintext structures are held in Python's memory heap during the active session. Ensure your host environment is fully secured against unauthorized local inspection, debugging, or memory dumping processes.
2. **Zero-Knowledge Recovery:** This architecture features a strict zero-knowledge model. There is no back-door, alternative recovery key, or bypass mechanism. If the master password is lost or forgotten, the underlying data payload cannot be recovered.