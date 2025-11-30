🔐 ASD•VAULT

ASD•VAULT is an AES-256-GCM encrypted password vault combined with a File Integrity Monitor (FIM).
It provides secure password storage, breach checking, strong password generation, and file-tamper detection.

🚀 Features
🔒 Encrypted Password Vault

AES-256-GCM encryption

Add, view, copy, delete entries

Clipboard auto-clear after 20 seconds

Delete only the password field (delete-pass)

Master password secured with Argon2id

One-time recovery key (cannot be regenerated)

🧠 Password Tools

Strength analysis (0–5 score)

Generate strong passwords (check generate)

Offline weak-password detection

Online breach exposure detection using HaveIBeenPwned (k-anonymity)

🛡 File Integrity Monitor (FIM)

Monitor any file or folder for changes

Detect unauthorized modifications

Optional background monitoring daemon

Alerts shown on next login

“Acknowledge Change” system updates trusted checksums

🖥 Command-Line Interface

Simple and clean terminal UI

Consistent command prompt:

< ASD•VAULT >

📦 Installation
1. Clone the repository
git clone https://github.com/<your-username>/asd-vault.git
cd asd-vault

2. Create & activate virtual environment
python3 -m venv venv
source venv/bin/activate

3. Install dependencies
pip install -r requirements.txt

4. Run ASD•VAULT
python -m asd_vault.cli


First run will:

Ask you to set a master password

Show a one-time recovery key

🕹 Commands Overview
Password Vault
add <name>          Add entry
list                List entries
get <name>          View username + password
copy <name>         Copy password (auto-clear in 20s)
delete <name>       Delete entry
delete-pass <name>  Clear only the password

Password Utilities
check <password>    Check strength (0–5)
check generate      Generate strong password
exposed <password>  Check breach exposure

File Integrity Monitor (FIM)
fim help            Detailed FIM help
fim add <path>      Add file/folder to monitor
fim list            Show monitored paths
fim scan            Manual scan
fim remove <path>   Stop monitoring
fim enable-bg       Enable background daemon
fim disable-bg      Disable daemon

🛠 Background Monitoring

To enable background tamper monitoring:

fim enable-bg


Then run daemon:

nohup python3 ~/.asd_vault/fim_daemon.py >/dev/null 2>&1 &


Daemon checks every 30 seconds and stores alerts in your encrypted vault.

⚠ Security Notes

Store your recovery key safely.

It can only reset the vault once.

After recovery is used, a new key will never be issued.

If you forget the new password → the vault is permanently locked.


🤝 Contributions

Pull requests and improvements are welcome.


Licensed under the MIT License (see LICENSE).

✔ Credits

Built by Asd 
alias Ro0tk1e
