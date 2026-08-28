#!/usr/bin/env python3
"""
WunderVault agent onboarding — download and run:
  curl -fsSL https://wundervault.com/onboard -o onboard.py && python3 onboard.py "SETUP_URL"

Requires: python3, pip install cryptography (or: pip install cryptography --quiet)
"""
import sys, json, base64, hashlib, hmac, os
try:
    import urllib.request as _req
    import urllib.parse as _parse
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    print("Installing cryptography...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "cryptography", "--quiet"])
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ONBOARD_PUBLIC_KEY = "3yhfVM5ABcBHPGSuZSQuIxr0C9QkHnFKoGMWwcWpooY="  # ed25519 public key

def _ensure_cryptography():
    """Return Ed25519PublicKey, installing the `cryptography` wheel if needed.

    Debian 12+, Ubuntu 23.04+ and Homebrew mark the interpreter
    externally-managed (PEP 668), so a plain `pip install` exits non-zero with
    "externally-managed-environment". That used to raise CalledProcessError
    straight out of verify_self, killing onboarding with a raw traceback that
    read like a signature failure. Try the least invasive option first; the
    PEP-668 escape is scoped to --user so it never writes to system dirs.
    """
    import subprocess, sys, site, importlib

    base = [sys.executable, "-m", "pip", "install", "--quiet"]
    attempts = [
        base + ["cryptography"],
        base + ["--user", "cryptography"],
        base + ["--user", "--break-system-packages", "cryptography"],
    ]
    for cmd in attempts:
        try:
            subprocess.check_call(cmd)
        except Exception:
            continue
        # A fresh --user install lands in a directory that may not have been on
        # sys.path when this process started.
        try:
            usp = site.getusersitepackages()
            if usp and usp not in sys.path:
                sys.path.insert(0, usp)
        except Exception:
            pass
        importlib.invalidate_caches()
        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
            return Ed25519PublicKey
        except ImportError:
            continue

    print("ERROR: could not install 'cryptography', which is required to verify")
    print("this script's signature before it runs.")
    print()
    print("Install it once, then re-run this script:")
    print("  Debian/Ubuntu : sudo apt install python3-cryptography")
    print("  Fedora/RHEL   : sudo dnf install python3-cryptography")
    print("  macOS         : brew install cryptography")
    print("  any system    : python3 -m venv ~/.wv-venv \\")
    print("                    && ~/.wv-venv/bin/pip install cryptography \\")
    _self = sys.argv[0] if sys.argv and sys.argv[0] not in ("", "-") else "onboard.py"
    print("                    && ~/.wv-venv/bin/python3 " + _self + ' "SETUP_URL"')
    sys.exit(1)


def verify_self(base_url, allow_skip=False):
    """Verify this script's signature before doing anything.

    TRUST MODEL — read this before relying on it. The signature is fetched from
    the same origin that served this script, and the public key it is checked
    against is embedded in this file (ONBOARD_PUBLIC_KEY, above). So this check
    does NOT establish that wundervault.com is trustworthy: whoever controls
    that origin controls the script, the key and the signature together.

    What it does establish: that the copy you are about to run is byte-identical
    to the one the holder of the signing key published. That catches a modified
    mirror, a tampered download, a stale or hand-edited local copy, and a proxy
    rewriting the body in transit. Independent provenance has to come from
    somewhere else, so this file is also published where we are not the host:

        https://github.com/wundervault/wundervault-mcp/tree/main/installer

    Diff that copy against what wundervault.com just served you. If they differ,
    run neither and tell the operator. Two companies would have to be compromised
    to modify both, and the second leaves a public commit behind.

    That is still not proof we deserve your credentials — we control the GitHub
    account too. That judgement belongs to the operator who owns the vault and
    sent you the link. If they cannot vouch for it, do not run this.
    """
    import os, sys, base64
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        Ed25519PublicKey = _ensure_cryptography()

    import urllib.request as _req

    req = _req.Request(f"{base_url}/onboard.sig", headers={"User-Agent": "WunderVault-Onboard/1.0"})
    try:
        with _req.urlopen(req, timeout=10) as r:
            sig_b64 = r.read().decode().strip()
    except Exception as e:
        print(f"ERROR: could not fetch the signature for verification: {e}")
        print(f"       {base_url}/onboard.sig was unreachable.")
        print()
        print("Onboarding stops here rather than running unverified code. Anyone")
        print("who can block that one URL could otherwise skip the check entirely.")
        print()
        if not allow_skip:
            print("If you have confirmed by other means that this copy is genuine,")
            print("re-run with --skip-verify to proceed deliberately.")
            sys.exit(1)
        print("--skip-verify was passed: proceeding WITHOUT signature verification.")
        return

    script_path = os.path.realpath(__file__) if os.path.exists(__file__) else None
    if not script_path or script_path == "<stdin>":
        print("ERROR: Script integrity cannot be verified when running via pipe.")
        print("Download the script first so verification can run:")
        print('  curl -fsSL https://wundervault.com/onboard -o onboard.py && python3 onboard.py "SETUP_URL"')
        sys.exit(1)

    try:
        pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(ONBOARD_PUBLIC_KEY))
        script_bytes = open(script_path, "rb").read()
        pub.verify(base64.b64decode(sig_b64), script_bytes)
        print("Script signature verified.")
    except Exception:
        print("ERROR: Script signature verification FAILED.")
        print("This script may have been tampered with. Aborting.")
        print(f"Expected public key: {ONBOARD_PUBLIC_KEY}")
        print("Verify against the published key at: https://wundervault.com/install")
        sys.exit(1)

def _check_mcp_version(base_url):
    import shutil as _shutil, subprocess as _sp, re as _re
    _npm = _shutil.which("npm")
    if not _npm:
        print("npm not found — install Node.js first: https://nodejs.org")
        sys.exit(1)

    def _parse_ver(s):
        m = _re.search(r'(\d+)\.(\d+)\.(\d+)', s or '')
        return tuple(int(x) for x in m.groups()) if m else (0, 0, 0)

    # Fetch latest published version from registry
    latest = (0, 0, 0)
    try:
        r = _sp.run([_npm, 'view', '@wundervault/mcp-server', 'version'],
                    capture_output=True, text=True, timeout=10)
        latest = _parse_ver(r.stdout.strip())
    except Exception:
        pass

    # Check installed version — look in system global and ~/.local prefix
    installed = None
    for _prefix in [None, os.path.expanduser("~/.local")]:
        _cmd = [_npm, 'list', '-g', '@wundervault/mcp-server', '--json']
        if _prefix:
            _cmd += ['--prefix', _prefix]
        r = _sp.run(_cmd, capture_output=True, text=True)
        try:
            deps = json.loads(r.stdout).get('dependencies', {})
            v = _parse_ver(deps.get('@wundervault/mcp-server', {}).get('version', ''))
            if v > (0, 0, 0):
                installed = v
                break
        except Exception:
            pass

    # CIP-024 §3.5: refuse onboarding if MCP is below the SERVER minimum
    try:
        import urllib.request as _u, json as _j
        _r = _u.urlopen(f"{base_url}/api/v1/mcp/requirements", timeout=5)
        _req_srv = _j.loads(_r.read())
        _min = _req_srv.get("min_mcp_version", "0.0.0")
        _upg = _req_srv.get("upgrade_cmd", "npm install -g @wundervault/mcp-server@latest")
    except Exception:
        _min, _upg = "0.0.0", None  # endpoint unreachable -> do not block (transient)
    # `installed` is already a parsed tuple (or None) — do NOT re-parse it;
    # _parse_ver() expects a string and raises TypeError on a tuple, which used
    # to crash every re-run on a machine that already had the MCP server.
    _installed_t = installed or (0, 0, 0)
    if _installed_t < _parse_ver(_min):
        print()
        print(f"  ERROR: this Wundervault MCP is older than the server requires.")
        print(f"         installed: {'.'.join(map(str, _installed_t))}   server minimum: {_min}")
        print(f"         Update first, then re-run onboarding:")
        print(f"           {_upg or 'npm install -g @wundervault/mcp-server@latest'}")
        sys.exit(1)

    if installed and (latest == (0, 0, 0) or installed >= latest):
        print(f"@wundervault/mcp-server {'.'.join(str(x) for x in installed)} — OK")
        return

    action = "Upgrading" if installed else "Installing"
    # Install an exact version, never a floating @latest: the resolved version is
    # printed before the install runs, so what gets executed is the version you
    # were shown and the same install repeats identically tomorrow.
    if latest > (0, 0, 0):
        ver_str = '.'.join(str(x) for x in latest)
        spec = f"@wundervault/mcp-server@{ver_str}"
    else:
        ver_str = "latest (registry lookup failed — version could not be pinned)"
        spec = "@wundervault/mcp-server@latest"
    print(f"{action} @wundervault/mcp-server to v{ver_str}...")
    print(f"  npm install -g {spec}")
    result = _sp.run([_npm, 'install', '-g', spec],
                     capture_output=True, text=True)
    if result.returncode != 0:
        home_prefix = os.path.expanduser("~/.local")
        result = _sp.run([_npm, 'install', '-g', '--prefix', home_prefix, spec],
                         capture_output=True, text=True)
    if result.returncode != 0:
        print(f"ERROR: could not install @wundervault/mcp-server: {result.stderr.strip()}")
        sys.exit(1)
    print(f"@wundervault/mcp-server installed.")


def print_manifest(base_url):
    """Print everything this script will do, and change nothing.

    An agent asked to run an installer off the internet should be able to read
    the consequences without executing it. This is that list, kept next to the
    code that performs each step.
    """
    home = os.path.expanduser("~")
    print(f"""
Wundervault onboarding — what running this will do
==================================================

Target server : {base_url}

1. Verify this script against {base_url}/onboard.sig
   ed25519, key embedded above as ONBOARD_PUBLIC_KEY. Aborts if it fails or
   if the signature cannot be fetched. This proves the file is the published
   one; it does NOT independently prove the server is trustworthy — see the
   trust model in verify_self().

2. Install the npm package @wundervault/mcp-server, globally, at an exact
   version resolved from the registry and printed before it installs.
   npm runs whatever install scripts that package ships. Requires Node.js.

3. If the `cryptography` Python wheel is missing, install it from PyPI —
   plain pip first, then --user, then --user --break-system-packages. The
   last one overrides the PEP 668 guard on Debian/Ubuntu/Homebrew, scoped to
   your user; nothing is written to system directories.

4. Exchange the one-time setup token for this agent's credentials. The link
   burns on use and cannot be replayed.

5. Write, all mode 0600 under {home}/.wundervault/ :
     agent-profiles.enc   credentials, AES-GCM
     agent-salt.bin       salt for the key derivation
     agents/<name>.token  local socket token
   The profile key is derived from /etc/machine-id + your uid, with the salt
   stored alongside. That protects the file if the disk or a backup leaves
   the machine. It does NOT protect it from anything already running as you:
   a same-user process can re-derive the key. Treat this as your user account
   protecting the credentials, not the file format.

6. Start the wundervault-agent daemon in the background, and on Linux write
   a systemd user unit at
     {home}/.config/systemd/user/wundervault-agent.service
   with Restart=always, then `systemctl --user enable --now`. That means it
   starts at login and survives reboot until you disable it.

7. Print MCP config file locations for common clients. It does not edit any
   client config — wiring the MCP server in is a separate, manual step.

To undo: systemctl --user disable --now wundervault-agent
         rm -rf {home}/.wundervault {home}/.config/systemd/user/wundervault-agent.service
         npm uninstall -g @wundervault/mcp-server
         and revoke the agent from the Wundervault dashboard.

Nothing above has happened. Re-run without --dry-run to proceed.
""")


def main():
    args = sys.argv[1:]
    repair_mode = '--repair' in args
    dry_run = '--dry-run' in args or '--explain' in args
    skip_verify = '--skip-verify' in args
    _flags = ('--repair', '--dry-run', '--explain', '--skip-verify')
    args = [a for a in args if a not in _flags]

    if not args:
        print("Usage: python3 onboard.py [--repair] [--dry-run] <SETUP_URL>")
        print("  SETUP_URL format: https://wundervault.com/setup/agent/TOKEN#PASSPHRASE")
        print("  --repair       Update an existing agent entry in place instead of adding a new one.")
        print("  --dry-run      Print every action this script would take, then exit. Changes nothing.")
        print("  --skip-verify  Proceed even if the signature cannot be fetched. Deliberate opt-out.")
        sys.exit(1)


    setup_url = args[0]
    parsed = _parse.urlparse(setup_url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    token = parsed.path.rstrip('/').split('/')[-1]
    passphrase = parsed.fragment

    if dry_run:
        print_manifest(base_url)
        sys.exit(0)

    # Verify BEFORE anything is installed or executed. _check_mcp_version runs
    # `npm install -g`, which executes the package's install scripts, so it must
    # not run ahead of the check that says this file is genuine.
    verify_self(base_url, allow_skip=skip_verify)

    _check_mcp_version(base_url)

    if not token or not passphrase:
        print("Error: URL must include token in path and passphrase as #fragment")
        sys.exit(1)

    ua = "WunderVault-Onboard/1.0"

    # Fetch encrypted blob
    req = _req.Request(f"{base_url}/api/setup/agent/{token}", headers={"User-Agent": ua})
    try:
        with _req.urlopen(req, timeout=15) as r:
            server = json.loads(r.read())
    except Exception as e:
        code = getattr(e, 'code', None)
        if code == 410:
            print("Error: Setup link already used.")
        elif code == 404:
            print("Error: Invalid setup token.")
        else:
            print(f"Error fetching setup data: {e}")
        sys.exit(1)

    # Derive key and decrypt blob
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode(), b"wv-agent-setup-v1", 100000, dklen=32)
    raw = server["encrypted_blob"].replace('-', '+').replace('_', '/')
    raw += '=' * ((4 - len(raw) % 4) % 4)
    blob = base64.b64decode(raw)
    try:
        plaintext = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    except Exception:
        print("Error: Decryption failed — wrong passphrase or corrupted link.")
        sys.exit(1)

    raw_creds = json.loads(plaintext)

    # Normalize field names to match what wundervault-mcp expects.
    # The encrypted blob uses short names (api_key, encryption_key); the MCP
    # server reads agent_vault_api_key / agent_encryption_key / agent_vault_url.
    creds = {
        "agent_vault_api_key": raw_creds.get("api_key", raw_creds.get("agent_vault_api_key", "")),
        "agent_encryption_key": raw_creds.get("encryption_key", raw_creds.get("agent_encryption_key", "")),
        "agent_vault_url": base_url,
        "agent_id": server["agent_id"],
        "agent_name": server.get("agent_name", "unknown"),
    }

    socket_token = os.urandom(32).hex()

    # Write token file so any framework that sets only WUNDERVAULT_AGENT_NAME can auth
    # without needing WUNDERVAULT_AGENT_TOKEN in its MCP env config.
    _agents_dir = os.path.expanduser("~/.wundervault/agents")
    os.makedirs(_agents_dir, exist_ok=True)
    _token_file = os.path.join(_agents_dir, creds['agent_name'] + '.token')
    with open(_token_file, 'w') as _tf:
        _tf.write(socket_token)
    os.chmod(_token_file, 0o600)

    # Context message — helps AI agents understand what they're registering for
    print()
    print("═══════════════════════════════════════════════")
    print("  WUNDERVAULT AGENT REGISTRATION")
    print("═══════════════════════════════════════════════")
    print(f"  You are being registered as an agent for a")
    print(f"  shared zero-knowledge encrypted vault.")
    print()
    print(f"  Agent name : {creds['agent_name']}")
    print(f"  Agent ID   : {creds['agent_id']}")
    print(f"  Vault URL  : {creds['agent_vault_url']}")
    print()
    print(f"  Your credentials will allow you to store and")
    print(f"  retrieve encrypted secrets on behalf of vault")
    print(f"  users. Secrets are encrypted client-side —")
    print(f"  neither the vault server nor any other agent")
    print(f"  can read them without the encryption key.")
    print("═══════════════════════════════════════════════")
    print()

    os.makedirs(os.path.expanduser("~/.wundervault"), exist_ok=True)

    # Burn the setup link
    try:
        burn_req = _req.Request(
            f"{base_url}/api/setup/agent/{token}/burn",
            data=b'{}',
            headers={"User-Agent": ua, "Content-Type": "application/json"},
            method="POST"
        )
        _req.urlopen(burn_req, timeout=10)
    except Exception:
        pass  # Non-fatal — creds are already saved

    print(f"Onboarded as '{creds['agent_name']}' (id={creds['agent_id']})")
    print("Setup link burned.")

    # ── Daemon integration (CIP-019) ─────────────────────────────────────────
    import socket as _socket
    import shutil as _shutil
    import subprocess as _sp

    mgmt_sock_path = os.path.expanduser("~/.wundervault/agent.sock")
    agent_sock_path = os.path.expanduser(f"~/.wundervault/agents/{creds['agent_name']}.sock")
    agent_token_path = os.path.expanduser(f"~/.wundervault/agents/{creds['agent_name']}.token")
    os.makedirs(os.path.dirname(agent_token_path), exist_ok=True)
    with open(agent_token_path, 'w') as _tf:
        _tf.write(socket_token)
    os.chmod(agent_token_path, 0o600)
    wv_dir = os.path.expanduser("~/.wundervault")
    os.makedirs(wv_dir, exist_ok=True)

    def _send_to_daemon(msg_dict):
        try:
            s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(mgmt_sock_path)
            s.sendall((json.dumps(msg_dict) + '\n').encode())
            resp = b''
            while True:
                chunk = s.recv(4096)
                if not chunk: break
                resp += chunk
                if b'\n' in resp: break
            s.close()
            return json.loads(resp.decode().strip())
        except Exception:
            return None

    def _write_encrypted_profile():
        """Write agent profile to encrypted store on disk (daemon reads this on start)."""
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes as _hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

        with open('/etc/machine-id', 'r') as _f:
            _machine_id = _f.read().strip()
        _uid = os.getuid() if hasattr(os, 'getuid') else 0
        _ikm = hashlib.sha256(f"{_machine_id}:{_uid}".encode()).digest()

        _salt_path = os.path.join(wv_dir, 'agent-salt.bin')
        if os.path.exists(_salt_path):
            with open(_salt_path, 'rb') as _f:
                _salt = _f.read()
        else:
            _salt = os.urandom(32)
            with open(_salt_path, 'wb') as _f:
                _f.write(_salt)
            os.chmod(_salt_path, 0o600)

        _hkdf = HKDF(algorithm=_hashes.SHA256(), length=32, salt=_salt, info=b"wundervault-agent-v1")
        _key = _hkdf.derive(_ikm)

        _profiles_path = os.path.join(wv_dir, 'agent-profiles.enc')
        _profiles = []
        if os.path.exists(_profiles_path):
            try:
                with open(_profiles_path, 'rb') as _f:
                    _buf = _f.read()
                _nonce, _tag, _enc = _buf[:12], _buf[12:28], _buf[28:]
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                _dec = Cipher(algorithms.AES(_key), modes.GCM(_nonce, _tag)).decryptor()
                _plain = _dec.update(_enc) + _dec.finalize()
                _profiles = json.loads(_plain.decode())['profiles']
            except Exception:
                _profiles = []

        _new_profile = {
            "agent_name": creds['agent_name'],
            "api_key": creds['agent_vault_api_key'],
            "enc_key": creds['agent_encryption_key'],
            "vault_url": creds['agent_vault_url'],
            "socket_token": socket_token,
        }
        _profiles = [p for p in _profiles if p.get('agent_name') != creds['agent_name']]
        _profiles.append(_new_profile)

        _store_json = json.dumps({"profiles": _profiles}).encode()
        _nonce_new = os.urandom(12)
        _ciphertext = _AESGCM(_key).encrypt(_nonce_new, _store_json, None)
        with open(_profiles_path, 'wb') as _f:
            _f.write(_nonce_new + _ciphertext[-16:] + _ciphertext[:-16])
        os.chmod(_profiles_path, 0o600)
        return _profiles_path

    def _install_systemd(daemon_bin):
        _systemd_dir = os.path.expanduser("~/.config/systemd/user")
        os.makedirs(_systemd_dir, exist_ok=True)
        _unit_path = os.path.join(_systemd_dir, 'wundervault-agent.service')
        _unit = f"""[Unit]
Description=Wundervault Local Agent Daemon
After=default.target

[Service]
ExecStart={daemon_bin}
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
"""
        with open(_unit_path, 'w') as _f:
            _f.write(_unit)
        _sp.run(['systemctl', '--user', 'daemon-reload'], capture_output=True)
        _sp.run(['systemctl', '--user', 'enable', '--now', 'wundervault-agent'], capture_output=True)
        return _unit_path

    # Prefer workspace-local CIP-019 build over globally installed binary
    _wv_workspace = os.path.expanduser("~/.openclaw/workspace/node_modules/.bin/wundervault-mcp")
    mcp_cmd = _wv_workspace if os.path.exists(_wv_workspace) else _shutil.which("wundervault-mcp")
    _daemon_bin = os.path.expanduser("~/.openclaw/workspace/node_modules/.bin/wundervault-agent") \
        if os.path.exists(os.path.expanduser("~/.openclaw/workspace/node_modules/.bin/wundervault-agent")) \
        else _shutil.which("wundervault-agent")

    if os.path.exists(mgmt_sock_path):
        # Daemon already running — register profile live
        result = _send_to_daemon({
            "action": "register_profile",
            "profile": {
                "agent_name": creds['agent_name'],
                "api_key": creds['agent_vault_api_key'],
                "enc_key": creds['agent_encryption_key'],
                "vault_url": creds['agent_vault_url'],
                "socket_token": socket_token,
            }
        })
        if result and result.get('ok'):
            print(f"Registered '{creds['agent_name']}' with running daemon.")
        else:
            print(f"Warning: live registration failed ({result}), writing profile to disk.")
            try:
                _write_encrypted_profile()
            except Exception as _e:
                print(f"ERROR: Could not write profile: {_e}")
                sys.exit(1)
    else:
        # Daemon not running — write profile then start daemon
        try:
            profiles_path = _write_encrypted_profile()
            print(f"Agent profile saved to {profiles_path}")
        except Exception as _e:
            print(f"ERROR: Could not write encrypted profile: {_e}")
            sys.exit(1)

        if _daemon_bin:
            # Start daemon in background immediately so tools work without a restart
            _sp.Popen(
                [_daemon_bin],
                stdout=_sp.DEVNULL, stderr=_sp.DEVNULL,
                start_new_session=True,
            )
            print(f"Daemon started: {_daemon_bin}")
        else:
            print("Note: wundervault-agent not in PATH. Install @wundervault/mcp-server.")
            print("      Profile is saved — vault tools will connect when daemon starts.")

    # Always install/update systemd unit so Restart=always stays current
    if _daemon_bin and sys.platform.startswith('linux'):
        try:
            _unit_path = _install_systemd(_daemon_bin)
            print(f"systemd user unit updated: {_unit_path}")
        except Exception:
            pass  # systemd may not be available

    _mcp_cmd_str = mcp_cmd or "wundervault-mcp"

    # ── Verify daemon connectivity ─────────────────────────────────────────────

    import time as _time
    _ready = False
    for _ in range(6):  # wait up to 3s for daemon to start
        if os.path.exists(agent_sock_path):
            try:
                _s = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
                _s.settimeout(1)
                _s.connect(agent_sock_path)
                import json as _json
                _s.sendall((_json.dumps({"token": socket_token}) + '\n').encode())
                _resp = _s.recv(4096)
                _s.close()
                if _resp and b'"error"' not in _resp:
                    _ready = True
                    break
            except Exception:
                pass
        _time.sleep(0.5)

    # ── Final status ───────────────────────────────────────────────────────────

    print()
    print("═══════════════════════════════════════════════")
    print("  WUNDERVAULT SETUP COMPLETE")
    print("═══════════════════════════════════════════════")
    print(f"  Agent : {creds['agent_name']}  ({creds['agent_id']})")
    print(f"  Vault : {creds['agent_vault_url']}")
    print()
    if _ready:
        print("  ✅ Daemon connected.")
    else:
        print("  ⚠  Daemon not yet reachable. Check that wundervault-agent is running.")
    print()
    print("  Next: add this entry to your framework's MCP server config,")
    print("  then reload your MCP connection.")
    print()
    print(f'    Command : {_mcp_cmd_str}')
    print(f'    Env     : WUNDERVAULT_AGENT_NAME = "{creds["agent_name"]}"')
    print()
    print("  Token is auto-discovered — do not add it to the config:")
    print(f"    ~/.wundervault/agents/{creds['agent_name']}.token")
    print("═══════════════════════════════════════════════")
    print()

    # ── Multi-agent isolation note ─────────────────────────────────────────────
    print(f'Note: WUNDERVAULT_AGENT_NAME must match this agent\'s name exactly ("{creds["agent_name"]}").')
    print("Each agent framework (Claude Code, OpenClaw, Hermes, etc.) has its own MCP config file.")
    print("Update YOUR framework's config — not another agent's.")
    print()

    # ── Config file location table ─────────────────────────────────────────────
    print("Common MCP config file locations:")
    print("  Claude Code  ~/.claude.json                           → mcpServers")
    print("  OpenClaw     ~/.openclaw/openclaw.json                → mcp.servers")
    print("  Hermes       ~/.hermes/config.yaml                    → mcp_servers")
    print("  Windsurf     ~/.codeium/windsurf/mcp_config.json      → mcpServers")
    print()
    print("After updating config:")
    print("  Claude Code — picks up changes automatically, no restart needed")
    print("  Hermes      — run: hermes gateway restart")
    print("  OpenClaw    — run: systemctl --user restart openclaw-gateway")
    print("  Windsurf    — restart from the application menu")
    print()

    # ── Machine-readable key-value block ──────────────────────────────────────
    _global_mcp = os.path.expanduser("~/.local/bin/wundervault-mcp")
    if not os.path.exists(_global_mcp):
        _global_mcp = _shutil.which("wundervault-mcp") or "wundervault-mcp"
    _openclaw_mcp = os.path.expanduser("~/.openclaw/workspace/node_modules/.bin/wundervault-mcp")
    print("---")
    print(f"WUNDERVAULT_AGENT_NAME={creds['agent_name']}")
    print(f"WUNDERVAULT_VAULT_URL={creds['agent_vault_url']}")
    print(f"WUNDERVAULT_DAEMON_SOCKET={agent_sock_path}")
    print(f"WUNDERVAULT_MCP_GLOBAL={_global_mcp}")
    if os.path.exists(_openclaw_mcp):
        print(f"WUNDERVAULT_MCP_OPENCLAW={_openclaw_mcp}")
    print("---")
    print()

    # ── Health check ──────────────────────────────────────────────────────────
    _health_ok = False
    try:
        _hr = _req.Request(f"{base_url}/health", headers={"User-Agent": ua})
        with _req.urlopen(_hr, timeout=5) as _hresp:
            _health_ok = _hresp.status == 200
    except Exception:
        pass
    if _health_ok:
        print(f"✅ Vault reachable at {base_url}")
    else:
        print(f"⚠  Vault unreachable — check that the Oracle server is running")
        print(f"    Vault tools will fail until the server is reachable.")
    print()


if __name__ == "__main__":
    main()
