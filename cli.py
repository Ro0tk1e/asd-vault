#!/usr/bin/env python3
"""
ASD•VAULT — Neon-themed AES-256-GCM encrypted vault + tamper monitor.
"""

import os, sys, json, time, uuid, getpass, secrets, base64, signal, hashlib, select
from pathlib import Path
from typing import Dict, Any, List

from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type as Argon2Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyperclip
import requests

BASE = Path.home() / ".asd_vault"
VAULT_FILE = BASE / "vault.json"

PH = PasswordHasher()

CURRENT_DEK = None
PROMPT = "< ASD•VAULT > "

ARGON2_TIME = 2
ARGON2_MEMORY = 65536
ARGON2_PARALLELISM = 2
KDF_LENGTH = 32

OFFLINE_COMMON = {
    "password","123456","12345678","qwerty","abc123","111111",
    "password1","letmein","iloveyou"
}

ANSI = {
    "r": "\033[0m",
    "b": "\033[1m",
    "g": "\033[92m",
    "c": "\033[96m",
    "y": "\033[93m",
    "red": "\033[91m",
}

def neon(text): return f"{ANSI['g']}{ANSI['b']}{text}{ANSI['r']}"

# -----------------------------------------------------------

def ensure_storage(): BASE.mkdir(parents=True, exist_ok=True)
def b64(b: bytes): return base64.b64encode(b).decode()
def ub64(s: str): return base64.b64decode(s.encode())

def derive_kek(password: str, salt: bytes) -> bytes:
    return hash_secret_raw(
        password.encode(), salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KDF_LENGTH,
        type=Argon2Type.ID
    )

def wrap_key(dek: bytes, kek: bytes) -> str:
    aes = AESGCM(kek)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, dek, None)
    return b64(nonce + ct)

def unwrap_key(wrapped: str, kek: bytes) -> bytes:
    raw = ub64(wrapped)
    aes = AESGCM(kek)
    return aes.decrypt(raw[:12], raw[12:], None)

def encrypt_with_dek(pt: bytes, dek: bytes):
    aes = AESGCM(dek)
    n = os.urandom(12)
    ct = aes.encrypt(n, pt, None)
    return b64(n), b64(ct)

def decrypt_with_dek(n, c, dek):
    aes = AESGCM(dek)
    return aes.decrypt(ub64(n), ub64(c), None)

# -----------------------------------------------------------

def create_vault(master_password: str) -> str:
    ensure_storage()
    salt_master = os.urandom(16)
    salt_recovery = os.urandom(16)
    dek = os.urandom(32)

    kek_master = derive_kek(master_password, salt_master)
    wrapped_master = wrap_key(dek, kek_master)

    recovery_key = secrets.token_urlsafe(32)
    kek_recovery = derive_kek(recovery_key, salt_recovery)
    wrapped_recovery = wrap_key(dek, kek_recovery)

    vault = {
        "vault_version": 3,
        "master_hash": PH.hash(master_password),
        "salt_master": b64(salt_master),
        "salt_recovery": b64(salt_recovery),
        "wrapped_dek_master": wrapped_master,
        "wrapped_dek_recovery": wrapped_recovery,
        "recovery_key_hash": PH.hash(recovery_key),
        "recovery_used": False,
        "entries": [],
        "fim": {
            "monitors": [],
            "alerts": []
        }
    }
    save_vault(vault)
    return recovery_key

def load_vault():
    if not VAULT_FILE.exists(): return None
    return json.load(open(VAULT_FILE))

def save_vault(v): json.dump(v, open(VAULT_FILE,"w"), indent=2)

# -----------------------------------------------------------

def unlock_vault_with_master(pw: str) -> bool:
    global CURRENT_DEK
    v = load_vault()
    if not v: return False
    try: PH.verify(v["master_hash"], pw)
    except: return False
    kek = derive_kek(pw, ub64(v["salt_master"]))
    try: CURRENT_DEK = unwrap_key(v["wrapped_dek_master"], kek)
    except: return False
    return True

def recover_with_recovery_key(rk, newpw):
    v = load_vault()
    if not v or v["recovery_used"]: return False
    try: PH.verify(v["recovery_key_hash"], rk)
    except: return False

    dek = unwrap_key(v["wrapped_dek_recovery"], derive_kek(rk, ub64(v["salt_recovery"])))
    salt_new = os.urandom(16)
    kek_new = derive_kek(newpw, salt_new)
    v["wrapped_dek_master"] = wrap_key(dek, kek_new)
    v["master_hash"] = PH.hash(newpw)
    v["salt_master"] = b64(salt_new)

    v["recovery_used"] = True
    for k in ("wrapped_dek_recovery","recovery_key_hash","salt_recovery"):
        v.pop(k,None)
    save_vault(v)
    return True

# -----------------------------------------------------------

def store_entry(name, user, pw):
    v = load_vault()
    n1,c1 = encrypt_with_dek(name.encode(), CURRENT_DEK)
    n2,c2 = encrypt_with_dek(user.encode(), CURRENT_DEK)
    n3,c3 = encrypt_with_dek(pw.encode(), CURRENT_DEK)
    v["entries"].append({
        "name":{"n":n1,"c":c1},
        "username":{"n":n2,"c":c2},
        "password":{"n":n3,"c":c3},
        "created_at":time.time()
    })
    save_vault(v)

def list_entries():
    v = load_vault()
    out=[]
    for e in v["entries"]:
        try: nm = decrypt_with_dek(e["name"]["n"],e["name"]["c"],CURRENT_DEK).decode()
        except: nm="<corrupt>"
        out.append(nm)
    return out

def get_entry(name):
    v=load_vault()
    for e in v["entries"]:
        try: nm = decrypt_with_dek(e["name"]["n"],e["name"]["c"],CURRENT_DEK).decode()
        except: continue
        if nm==name:
            user = decrypt_with_dek(e["username"]["n"],e["username"]["c"],CURRENT_DEK).decode()
            pw   = decrypt_with_dek(e["password"]["n"],e["password"]["c"],CURRENT_DEK).decode()
            return {"name":nm,"username":user,"password":pw}
    return None

def delete_entry(name):
    v=load_vault()
    new=[]
    removed=False
    for e in v["entries"]:
        nm=decrypt_with_dek(e["name"]["n"],e["name"]["c"],CURRENT_DEK).decode()
        if nm==name: removed=True
        else: new.append(e)
    v["entries"]=new
    save_vault(v)
    return removed

def delete_password_field(name):
    v=load_vault()
    for e in v["entries"]:
        nm=decrypt_with_dek(e["name"]["n"],e["name"]["c"],CURRENT_DEK).decode()
        if nm==name:
            n,c=encrypt_with_dek(b"",CURRENT_DEK)
            e["password"]={"n":n,"c":c}
            save_vault(v)
            return True
    return False

# -----------------------------------------------------------

def secure_wipe_dek():
    global CURRENT_DEK
    if CURRENT_DEK:
        arr=bytearray(CURRENT_DEK)
        for i in range(len(arr)): arr[i]=0
    CURRENT_DEK=None

signal.signal(signal.SIGINT, lambda s,f:(secure_wipe_dek(),sys.exit(0)) )
signal.signal(signal.SIGTERM, lambda s,f:(secure_wipe_dek(),sys.exit(0)) )

# -----------------------------------------------------------

def banner():
    line = neon("===========================================")
    print(line)
    print(neon("          🔐  ASD • VAULT  🔐"))
    print(line+"\n")

def show_welcome():
    banner()
    print(neon("Welcome, Asd.") )
    print("Your vault is protected with AES-256-GCM.\n")
    print(neon("Security Modules:"))
    print("  • Password Vault (encrypted)")
    print("  • Integrity Monitor (file tamper detection)\n")
    print("Integrity Monitor:")
    print("  Tracks files/folders you choose and alerts on unauthorized changes.\n")
    print("Use 'fim help' to see full guidance.\n")
    print("Type 'help' to view vault commands.\n")

# -----------------------------------------------------------

def copy_with_autoclear(text):
    try: pyperclip.copy(text)
    except: print("Clipboard unavailable.\n"); return
    print(neon("✓ Password copied to clipboard."))
    print("Auto-clear in 20s. Press ENTER to clear now.")
    for t in range(20,0,-1):
        r,_,_=select.select([sys.stdin],[],[],1)
        if r:
            sys.stdin.readline()
            pyperclip.copy("")
            print("\nClipboard cleared.\n")
            return
        sys.stdout.write(f"\rClearing in: {t}s")
        sys.stdout.flush()
    pyperclip.copy("")
    print("\nClipboard cleared.\n")

# -----------------------------------------------------------

def exposed_check(p):
    if p.lower() in OFFLINE_COMMON:
        return {"offline":True,"online":None}
    sha=hashlib.sha1(p.encode()).hexdigest().upper()
    prefix, tail = sha[:5], sha[5:]
    try:
        r=requests.get(f"https://api.pwnedpasswords.com/range/{prefix}",timeout=7)
        if r.status_code!=200: return {"offline":False,"online":None}
        for line in r.text.splitlines():
            h,c=line.split(":")
            if h==tail: return {"offline":False,"online":int(c)}
        return {"offline":False,"online":0}
    except:
        return {"offline":False,"online":None}

# -----------------------------------------------------------
# FIM: hashing
# -----------------------------------------------------------

def hash_file(p: Path):
    h=hashlib.sha256()
    try:
        with p.open("rb") as f:
            while True:
                b=f.read(8192)
                if not b: break
                h.update(b)
        return h.hexdigest()
    except: return ""

def hash_dir(p: Path):
    items=[]
    for root,dirs,files in os.walk(p):
        files.sort(); dirs.sort()
        for f in files:
            fp=Path(root)/f
            rel=os.path.relpath(fp,p)
            items.append(f"{rel}:{hash_file(fp)}")
    return hashlib.sha256("\n".join(items).encode()).hexdigest()

def compute_hash(path):
    p=Path(path)
    if not p.exists(): return ""
    if p.is_file(): return hash_file(p)
    return hash_dir(p)

# -----------------------------------------------------------
# FIM operations
# -----------------------------------------------------------

def fim_add(path, bg):
    v=load_vault()
    p=str(Path(path).expanduser())
    if not Path(p).exists(): return False
    h=compute_hash(p)
    for m in v["fim"]["monitors"]:
        if m["path"]==p: return False
    v["fim"]["monitors"].append({
        "path":p,
        "is_dir":Path(p).is_dir(),
        "monitor_bg": bg,
        "last_hash":h,
        "added_at":time.time()
    })
    save_vault(v); return True

def fim_remove(path):
    v=load_vault()
    p=str(Path(path).expanduser())
    old=len(v["fim"]["monitors"])
    v["fim"]["monitors"]=[m for m in v["fim"]["monitors"] if m["path"]!=p]
    save_vault(v)
    return len(v["fim"]["monitors"])!=old

def fim_list(): return load_vault()["fim"]["monitors"]

def fim_scan():
    v=load_vault()
    new=[]
    for m in v["fim"]["monitors"]:
        cur=compute_hash(m["path"])
        if cur!=m["last_hash"]:
            new.append({
                "path":m["path"],
                "type":"missing" if cur=="" else "modified",
                "previous":m["last_hash"],
                "current":cur,
                "detected_at":time.time()
            })
    if new:
        v["fim"]["alerts"].extend(new)
        save_vault(v)
    return new

def fim_ack(idx):
    v=load_vault()
    if idx<0 or idx>=len(v["fim"]["alerts"]): return False
    a=v["fim"]["alerts"].pop(idx)
    for m in v["fim"]["monitors"]:
        if m["path"]==a["path"]:
            m["last_hash"]=a["current"]
            break
    save_vault(v)
    return True

# -----------------------------------------------------------
# FIM daemon helper
# -----------------------------------------------------------

DAEMON = BASE/"fim_daemon.py"
DAEMON_CODE = r'''#!/usr/bin/env python3
import os, time, hashlib, json
from pathlib import Path

BASE = Path.home()/".asd_vault"
VAULT = BASE/"vault.json"

def hash_file(p):
    h=hashlib.sha256()
    try:
        with open(p,"rb") as f:
            while True:
                b=f.read(8192)
                if not b: break
                h.update(b)
        return h.hexdigest()
    except: return ""

def hash_dir(p):
    items=[]
    for r,dirs,files in os.walk(p):
        files.sort()
        for f in files:
            fp=Path(r)/f
            rel=os.path.relpath(fp,p)
            items.append(f"{rel}:{hash_file(fp)}")
    return hashlib.sha256("\n".join(items).encode()).hexdigest()

def compute(p):
    p=Path(p)
    if not p.exists(): return ""
    return hash_file(p) if p.is_file() else hash_dir(p)

def main():
    while True:
        try:
            if not VAULT.exists():
                time.sleep(30); continue
            v=json.load(open(VAULT))
            new=[]
            for m in v["fim"]["monitors"]:
                if not m["monitor_bg"]: continue
                cur=compute(m["path"])
                if cur!=m["last_hash"]:
                    new.append({
                        "path":m["path"],
                        "type":"missing" if cur=="" else "modified",
                        "previous":m["last_hash"],
                        "current":cur,
                        "detected_at":time.time()
                    })
            if new:
                v["fim"]["alerts"].extend(new)
                json.dump(v,open(VAULT,"w"),indent=2)
        except: pass
        time.sleep(30)

if __name__=="__main__": main()
'''

def fim_enable_bg():
    ensure_storage()
    open(DAEMON,"w").write(DAEMON_CODE)
    os.chmod(DAEMON,0o755)
    msg=f"Run in background:\n  nohup python3 {DAEMON} >/dev/null 2>&1 &"
    return msg

def fim_disable_bg():
    if DAEMON.exists(): DAEMON.unlink()
    return True

# -----------------------------------------------------------
# HELP system
# -----------------------------------------------------------

def help_detail(cmd):
    cmd=cmd.lower()
    if cmd=="add":
        print("""
add <name>
  Add password entry.
  Username + Password required.
"""); return
    if cmd=="list":
        print("list\n  Show all entry names.\n"); return
    if cmd=="get":
        print("get <name>\n  Show username + password.\n"); return
    if cmd=="copy":
        print("copy <name>\n  Copy password (auto-clear in 20s).\n"); return
    if cmd=="delete":
        print("delete <name>\n  Remove entry completely.\n"); return
    if cmd=="delete-pass":
        print("delete-pass <name>\n  Clear only the password.\n"); return
    if cmd=="check":
        print("""
check <password>     Check strength
check generate       Generate strong password
"""); return
    if cmd=="exposed":
        print("exposed <password>\n  Check breach exposure.\n"); return
    if cmd=="fim":
        print("""
fim add <path>       Add file/folder to monitor
fim scan             Scan for changes
fim list             Show monitored paths
fim remove <path>    Stop monitoring
fim enable-bg        Create daemon helper
fim disable-bg       Remove daemon
"""); return
    print("Unknown command\n")

def help_menu():
    print("""
Commands:
  add <name>         Add entry
  list               List entries
  get <name>         View entry
  copy <name>        Copy password
  delete <name>      Delete entry
  delete-pass <name> Clear password only
  check <pass>       Strength check
  check generate     Secure password
  exposed <pass>     Breach check
  fim help           FIM help
  help <command>     Detail help
  exit               Quit
""")

# -----------------------------------------------------------
# Main shell
# -----------------------------------------------------------

def first_time_setup():
    show_welcome()
    print("No vault found — starting setup.\n")
    pw = getpass.getpass("Create MASTER PASSWORD (blank → auto-generate): ")
    if not pw:
        pw=secrets.token_urlsafe(18)
        print("\nGenerated master password:\n  "+pw+"\n")
    print("\nYou will now receive a ONE-TIME recovery key.")
    input("Press ENTER to continue.")
    rk = create_vault(pw)
    print("\nRECOVERY KEY (displayed once):\n  "+rk+"\n")
    print("Press ENTER to skip the timer or wait 120s.")
    for t in range(120,0,-1):
        r,_,_ = select.select([sys.stdin],[],[],1)
        if r:
            sys.stdin.readline()
            print("\nRecovery key display skipped.\n")
            return
        sys.stdout.write(f"\rTime remaining: {t}s")
        sys.stdout.flush()
    print("\n")

def interactive():
    ensure_storage()
    if not VAULT_FILE.exists():
        first_time_setup()

    # unlock
    for i in range(3):
        pw=getpass.getpass("Enter master password: ")
        if unlock_vault_with_master(pw): break
        print(f"Incorrect ({i+1}/3)")
    else:
        v=load_vault()
        print("\nMaster password incorrect 3/3.")
        if v.get("recovery_used"):
            print("Recovery key already consumed. Vault locked.\n"); sys.exit(1)
        yn=input("Enter recovery mode? (Y/n): ").lower()
        if yn in ("","y"):
            rk=getpass.getpass("Recovery key: ")
            new=getpass.getpass("New master password: ")
            if new!=getpass.getpass("Confirm: "):
                print("Mismatch."); sys.exit(1)
            if not recover_with_recovery_key(rk,new):
                print("Recovery failed."); sys.exit(1)
            if not unlock_vault_with_master(new):
                print("Unlock failed."); sys.exit(1)
        else:
            sys.exit(0)

    show_welcome()

    # Alerts
    v=load_vault()
    alerts=v["fim"]["alerts"]
    if alerts:
        print(neon("⚠ FILE INTEGRITY ALERTS DETECTED"))
        for i,a in enumerate(alerts,1):
            t=time.strftime("%Y-%m-%d %H:%M:%S",time.localtime(a["detected_at"]))
            print(f"\n{i}) {a['path']} — {a['type']} @ {t}")
            print(f"   Previous: {a['previous']}")
            print(f"   Current : {a['current']}")
        print()
        for i in range(len(alerts)):
            yn=input(f"Acknowledge #{i+1}? (Y/n): ").lower()
            if yn in ("","y"):
                fim_ack(i)
                print("  Updated.\n")

    # Loop
    while True:
        try: line=input(neon(PROMPT)).strip()
        except: secure_wipe_dek(); sys.exit(0)
        if not line: continue

        parts=line.split()
        cmd=parts[0].lower()
        args=parts[1:]

        if cmd=="exit": secure_wipe_dek(); sys.exit(0)
        if cmd=="help":
            if not args: help_menu()
            else: help_detail(args[0])
            continue
        if cmd=="add":
            if not args: print("Usage: add <name>\n"); continue
            nm=args[0]
            user=input("Username: ")
            pw=getpass.getpass("Password: ")
            if not pw: print("Password required.\n"); continue
            store_entry(nm,user,pw)
            print(neon("✓ Saved.")+"\n"); continue
        if cmd=="list":
            names=list_entries()
            for i,nm in enumerate(names,1): print(f"{i}) {nm}")
            print(); continue
        if cmd=="get":
            if not args: print("Usage: get <name>\n"); continue
            e=get_entry(args[0])
            if not e: print("Not found.\n")
            else:
                print("Name:",e["name"])
                print("Username:",e["username"])
                print("Password:",e["password"],"\n")
            continue
        if cmd=="copy":
            if not args: print("Usage: copy <name>\n"); continue
            e=get_entry(args[0])
            if not e: print("Not found.\n")
            else: copy_with_autoclear(e["password"])
            continue
        if cmd=="delete":
            if not args: print("Usage: delete <name>\n"); continue
            if delete_entry(args[0]): print(neon("✓ Deleted.")+"\n")
            else: print("Not found.\n")
            continue
        if cmd=="delete-pass":
            if not args: print("Usage: delete-pass <name>\n"); continue
            if delete_password_field(args[0]): print(neon("✓ Password cleared.")+"\n")
            else: print("Not found.\n")
            continue
        if cmd=="check":
            if not args:
                print("Usage: check <pw> | check generate\n"); continue
            if args[0]=="generate":
                pw=secrets.token_urlsafe(18)
                print("\nStrong password:\n  "+pw+"\n"); continue
            p=args[0]
            length=len(p)>=12
            upper=any(c.isupper() for c in p)
            lower=any(c.islower() for c in p)
            digit=any(c.isdigit() for c in p)
            sym=any(not c.isalnum() for c in p)
            score=sum([length,upper,lower,digit,sym])
            print(f"Strength: {score}/5\n")
            if score<5:
                yn=input("Generate 5/5 password? (Y/n): ").lower()
                if yn in ("","y"):
                    pw=secrets.token_urlsafe(18)
                    print("\nStrong password:\n  "+pw+"\n")
            continue
        if cmd=="exposed":
            if not args: print("Usage: exposed <pw>\n"); continue
            r=exposed_check(args[0])
            if r["offline"]: print("⚠ Offline common password.\n")
            elif r["online"] is None: print("Offline — cannot contact server.\n")
            elif r["online"]==0: print(neon("✓ No known breaches.")+"\n")
            else: print(f"⚠ Found {r['online']} breaches.\n")
            continue

        if cmd=="fim":
            if not args: print("Use: fim help\n"); continue
            sub=args[0].lower()
            if sub=="help": help_detail("fim"); continue
            if sub=="add":
                if len(args)<2: print("Usage: fim add <path>\n"); continue
                bg = input("Enable background monitoring? (Y/n): ").lower() in ("","y")
                if fim_add(args[1],bg): print(neon("✓ Added.")+"\n")
                else: print("Cannot add (exists/missing).\n")
                continue
            if sub=="list":
                mons=fim_list()
                if not mons: print("No paths.\n")
                else:
                    for i,m in enumerate(mons,1):
                        print(f"{i}) {m['path']} (BG:{'Yes' if m['monitor_bg'] else 'No'})")
                    print()
                continue
            if sub=="remove":
                if len(args)<2: print("Usage: fim remove <path>\n"); continue
                if fim_remove(args[1]): print(neon("✓ Removed.")+"\n")
                else: print("Not found.\n")
                continue
            if sub=="scan":
                found=fim_scan()
                if not found: print("No changes.\n")
                else:
                    print(neon("New alerts:"))
                    for a in found:
                        print("  ",a["path"],a["type"])
                    print()
                continue
            if sub=="enable-bg":
                print(neon("Daemon ready."))
                print(fim_enable_bg(),"\n")
                continue
            if sub=="disable-bg":
                fim_disable_bg()
                print(neon("✓ Daemon removed.")+"\n")
                continue

            print("Unknown fim command.\n")
            continue

        print("Unknown command.\n")

# -----------------------------------------------------------

def main(): interactive()

if __name__=="__main__":
    main()
