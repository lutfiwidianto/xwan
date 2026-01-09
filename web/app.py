from __future__ import annotations

import builtins
import contextlib
import csv
import io
import json
import os
import socket
import sys
import traceback
import sqlite3
import secrets
import time
from urllib.parse import urlencode
from pathlib import Path
from typing import Iterable

import httpx
from authlib.integrations.flask_client import OAuth
from flask import Flask, Response, abort, redirect, render_template, request, send_file, session, stream_with_context, url_for

ROOT_DIR = Path(__file__).resolve().parents[1]
CLI_DIR = ROOT_DIR / "cli"
DATA_DIR = ROOT_DIR / "data"
OUTPUT_DIR = ROOT_DIR / "output"
TMP_DIR = ROOT_DIR / "tmp"

for path in (DATA_DIR, OUTPUT_DIR, TMP_DIR):
    path.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(CLI_DIR))

from modules import keyword_search, onering, parse, revip, ssh_ws, subdomain, test_xray
from utils import helpers

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "xwan-dev-key")

RESULT_FILE = OUTPUT_DIR / "Result.txt"
SUBDOMAIN_STATE = {
    "scan_id": None,
    "domain": None,
    "rows": [],
    "subdomains": [],
    "index": 0,
    "cancel": False,
}

DB_PATH = DATA_DIR / "xwan.db"


def _init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subdomain_scans (
                scan_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS subdomain_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                subdomain TEXT NOT NULL,
                ip TEXT,
                hostname TEXT,
                status TEXT,
                provider TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT,
                picture TEXT,
                last_login TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_devices (
                api_key TEXT PRIMARY KEY,
                user_email TEXT,
                device_name TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_jobs (
                job_id TEXT PRIMARY KEY,
                api_key TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                target TEXT NOT NULL,
                mode TEXT NOT NULL,
                success INTEGER NOT NULL,
                error TEXT,
                created_at TEXT NOT NULL
            )
            """
        )
        _db_add_column_if_missing(conn, "subdomain_scans", "user_email", "TEXT")
        _db_add_column_if_missing(conn, "agent_devices", "last_seen", "TEXT")


def _db_add_column_if_missing(conn: sqlite3.Connection, table: str, column: str, column_type: str) -> None:
    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})")]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {column_type}")


oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


def _db_execute(query: str, params: tuple = ()) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(query, params)
        conn.commit()


def _db_fetchall(query: str, params: tuple = ()) -> list[dict]:
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(query, params).fetchall()
    return [dict(row) for row in rows]

SCAN_MODES = {
    "address": {
        "title": "Xray Address",
        "help": "Scan target langsung menggunakan address mode.",
    },
    "wildcard": {
        "title": "Xray Wildcard",
        "help": "Scan target menggunakan wildcard address.",
    },
    "sni": {
        "title": "Xray SNI",
        "help": "Scan target dengan SNI khusus.",
    },
    "onering": {
        "title": "Xray Onering",
        "help": "Mode onering sesuai config VPN.",
    },
    "auto": {
        "title": "Xray Auto All Modes",
        "help": "Menjalankan semua mode Xray (1,2,3,4).",
    },
}

SIMPLE_PAGES = {
    "ssh-ws": {
        "title": "SSH Websocket",
        "description": "Jalankan flow ssh_ws dengan input dari web.",
    },
    "subdomain": {
        "title": "Subdomain Scanner",
        "description": "Menjalankan modul subdomain dan simpan hasil ke domain.txt.",
    },
    "reverse-ip": {
        "title": "Reverse IP",
        "description": "Menjalankan modul reverse IP dan simpan hasil ke rev_ip.txt.",
    },
    "keyword-search": {
        "title": "Keyword Domain Search",
        "description": "Menjalankan modul keyword search dan simpan hasil ke file output.",
    },
}


def _capture_run(func, inputs: Iterable[str]) -> tuple[str, str | None]:
    input_iter = iter(inputs)

    def _fake_input(prompt: str = "") -> str:
        try:
            return next(input_iter)
        except StopIteration:
            return ""

    output = io.StringIO()
    error = None
    original_input = builtins.input

    try:
        builtins.input = _fake_input
        with contextlib.redirect_stdout(output):
            func()
    except Exception:
        error = traceback.format_exc()
        output.write("\n[ERROR] Terjadi error saat menjalankan proses.\n")
    finally:
        builtins.input = original_input

    return output.getvalue(), error


def _safe_bool(value: str | None) -> bool:
    return value in {"1", "true", "True", "on", "yes", "y"}


def _write_ssh_accounts(accounts, path: Path) -> None:
    ssh_ws.ACCOUNTS_FILE = path
    ssh_ws._save_accounts(accounts)


def _load_ssh_accounts(path: Path):
    ssh_ws.ACCOUNTS_FILE = path
    return ssh_ws._load_accounts()


def _load_targets_from_upload(file_storage) -> list[str]:
    if not file_storage:
        return []
    try:
        content = file_storage.read().decode("utf-8", errors="ignore")
    except Exception:
        return []
    lines = []
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


def run_xray_scan(
    mode: str,
    url: str,
    list_file: str,
    sni: str | None,
    target_domain: str | None,
    upload_file,
    execution_mode: str,
):
    errors = []
    if not url:
        errors.append("URL akun wajib diisi.")

    targets = []
    if mode == "auto":
        if target_domain:
            targets = [target_domain]
        else:
            targets = _load_targets_from_upload(upload_file)
            if not targets and list_file:
                list_path = Path(list_file)
                if not list_path.is_absolute():
                    candidate = DATA_DIR / list_file
                    if candidate.exists():
                        list_path = candidate
                if list_path.exists():
                    targets = test_xray.load_addresses_from_file(str(list_path))
                else:
                    errors.append("File list tidak ditemukan.")
        if not targets:
            errors.append("Domain atau file list wajib diisi.")
    else:
        if not list_file:
            errors.append("List IP/domain wajib diisi.")
        list_path = Path(list_file)
        if list_file and not list_path.is_absolute():
            candidate = DATA_DIR / list_file
            if candidate.exists():
                list_path = candidate
        if list_file and not list_path.exists():
            errors.append("File list tidak ditemukan.")
        if list_file and list_path.exists():
            targets = test_xray.load_addresses_from_file(str(list_path))

    if errors:
        return {"errors": errors, "results": [], "summary": None, "account": None}

    if mode == "auto" and execution_mode == "agent":
        api_key = _get_or_create_agent_key()
        job_id = f"job-{int(time.time())}-{secrets.token_hex(4)}"
        payload = {
            "job_id": job_id,
            "mode": mode,
            "url": url,
            "sni": sni or "",
            "targets": targets,
        }
        _db_execute(
            "INSERT INTO agent_jobs (job_id, api_key, payload, status, created_at) VALUES (?, ?, ?, ?, datetime('now'))",
            (job_id, api_key, json.dumps(payload), "pending"),
        )
        return {
            "errors": [],
            "results": [],
            "summary": {
                "queued": True,
                "job_id": job_id,
                "targets": len(targets),
            },
            "account": None,
        }

    try:
        account = parse.parse_vmess_trojan_url(url)
    except Exception as exc:
        return {
            "errors": [f"Gagal parsing URL: {exc}"],
            "results": [],
            "summary": None,
            "account": None,
        }

    if not targets:
        return {
            "errors": ["Target kosong atau tidak ada di file list."],
            "results": [],
            "summary": None,
            "account": account,
        }

    mode_map = {
        "address": "1",
        "wildcard": "2",
        "sni": "3",
        "onering": "4",
        "auto": "9",
    }
    mode_labels = {
        "1": "Address",
        "2": "Wildcard",
        "3": "SNI",
        "4": "Onering",
        "9": "Auto All Modes",
    }

    choice = mode_map[mode]
    active_modes = ["1", "2", "3", "4"] if choice == "9" else [choice]

    results = []
    success_count = 0

    for target in targets:
        for m in active_modes:
            mode_name = mode_labels[m]
            try:
                helpers.kill_xray_processes()
            except Exception:
                pass
            success = False
            error_msg = None

            try:
                if m == "4":
                    success, _ = onering.test_onering(target, account)
                elif m == "2":
                    success = test_xray.test_wildcard_address(target, account)
                elif m == "3":
                    sni_target = sni.strip() if sni else target
                    success = test_xray.test_address(None, account, sni_target)
                elif m == "1":
                    success = test_xray.test_address(target, account)
            except Exception as exc:
                error_msg = str(exc)

            if success:
                success_count += 1
                with open(RESULT_FILE, "a", encoding="utf-8") as f:
                    f.write(
                        f"Domain: {target} | Mode: {mode_name} | Account: {account['address']}\n"
                    )

            results.append(
                {
                    "target": target,
                    "mode": mode_name,
                    "success": success,
                    "error": error_msg,
                }
            )

    summary = {
        "total_targets": len(targets),
        "total_success": success_count,
        "modes": [mode_labels[m] for m in active_modes],
        "result_file": str(RESULT_FILE),
    }

    return {
        "errors": [],
        "results": results,
        "summary": summary,
        "account": account,
    }


def _resolve_host(host: str) -> tuple[str | None, str | None]:
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        return None, None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        hostname = None
    return ip, hostname


def _detect_provider(headers: dict, hostname: str | None) -> str:
    header_lower = {k.lower(): v for k, v in headers.items()}
    server = header_lower.get("server", "").lower()
    via = header_lower.get("via", "").lower()

    if "cf-ray" in header_lower or "cloudflare" in server:
        return "Cloudflare"
    if "x-akamai-transformed" in header_lower or "akamai" in server:
        return "Akamai"
    if "x-amz-cf-id" in header_lower or "cloudfront" in server or "cloudfront" in via:
        return "CloudFront"
    if "fastly" in server or "fastly" in via:
        return "Fastly"
    if "incap" in server or "imperva" in server:
        return "Imperva"
    if "gcore" in server:
        return "Gcore"
    return hostname or "-"


def _fetch_subdomains(domain: str) -> tuple[list[str], str | None]:
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    try:
        with httpx.Client(timeout=15) as client:
            api_url = f"https://api.subdomainfinder.in/?domain={domain}"
            response = client.get(api_url, headers=headers)
            response.raise_for_status()

            try:
                payload = response.json()
            except ValueError:
                return [], "Respon API tidak valid."

            subdomains = set()
            data_items = payload.get("data") or []
            for item in data_items:
                subdomain = str(item.get("subdomain", "")).strip()
                if subdomain:
                    subdomains.add(subdomain)

            # CT logs (crt.sh)
            try:
                ct_url = f"https://crt.sh/?q=%25.{domain}&output=json"
                ct_resp = client.get(ct_url, headers=headers)
                if ct_resp.status_code == 200:
                    try:
                        ct_data = ct_resp.json()
                        for entry in ct_data:
                            name = str(entry.get("name_value", "")).strip()
                            for line in name.splitlines():
                                value = line.strip().lower()
                                if value.endswith(domain.lower()):
                                    subdomains.add(value)
                    except ValueError:
                        pass
            except httpx.RequestError:
                pass
    except httpx.RequestError as exc:
        return [], f"Gagal ambil data: {exc}"

    # Brute-force wordlist
    wordlist_path = DATA_DIR / "subdomains.txt"
    if wordlist_path.exists():
        try:
            words = [w.strip() for w in wordlist_path.read_text(encoding="utf-8").splitlines() if w.strip()]
            for word in words:
                subdomains.add(f"{word}.{domain}")
        except Exception:
            pass

    if not subdomains:
        return [], "Tidak ada subdomain ditemukan."

    return sorted(subdomains), None


def _db_insert_scan(scan_id: str, domain: str) -> None:
    user_email = session.get("user_email")
    _db_execute(
        "INSERT OR REPLACE INTO subdomain_scans (scan_id, domain, created_at, user_email) VALUES (?, ?, datetime('now'), ?)",
        (scan_id, domain, user_email),
    )
    _db_execute("DELETE FROM subdomain_results WHERE scan_id = ?", (scan_id,))


def _db_insert_row(scan_id: str, row: dict) -> None:
    _db_execute(
        """
        INSERT INTO subdomain_results (scan_id, subdomain, ip, hostname, status, provider, created_at)
        VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """,
        (
            scan_id,
            row["subdomain"],
            row["ip"],
            row["hostname"],
            row["status"],
            row["provider"],
        ),
    )


def _db_get_cached_rows(domain: str) -> list[dict]:
    scans = _db_fetchall(
        "SELECT scan_id FROM subdomain_scans WHERE domain = ? ORDER BY created_at DESC LIMIT 1",
        (domain,),
    )
    if not scans:
        return []
    scan_id = scans[0]["scan_id"]
    return _db_fetchall(
        """
        SELECT subdomain, ip, hostname, status, provider
        FROM subdomain_results
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    )


def _db_get_scans() -> list[dict]:
    user_email = session.get("user_email")
    if user_email:
        return _db_fetchall(
            """
            SELECT scan_id, domain, created_at
            FROM subdomain_scans
            WHERE user_email = ?
            ORDER BY created_at DESC
            """,
            (user_email,),
        )
    return _db_fetchall(
        """
        SELECT scan_id, domain, created_at
        FROM subdomain_scans
        ORDER BY created_at DESC
        """,
    )


def _db_get_results(scan_id: str) -> list[dict]:
    return _db_fetchall(
        """
        SELECT subdomain, ip, hostname, status, provider
        FROM subdomain_results
        WHERE scan_id = ?
        ORDER BY id ASC
        """,
        (scan_id,),
    )


def _upsert_user(email: str, name: str, picture: str) -> None:
    _db_execute(
        """
        INSERT INTO users (email, name, picture, last_login)
        VALUES (?, ?, ?, datetime('now'))
        ON CONFLICT(email) DO UPDATE SET
          name=excluded.name,
          picture=excluded.picture,
          last_login=datetime('now')
        """,
        (email, name, picture),
    )


def _current_user() -> dict | None:
    if not session.get("user_email"):
        return None
    return {
        "email": session.get("user_email"),
        "name": session.get("user_name"),
        "picture": session.get("user_picture"),
    }


def _get_or_create_agent_key() -> str:
    user_email = session.get("user_email")
    rows = _db_fetchall(
        "SELECT api_key FROM agent_devices WHERE user_email IS ? ORDER BY created_at DESC LIMIT 1",
        (user_email,),
    )
    if rows:
        return rows[0]["api_key"]
    api_key = secrets.token_hex(16)
    _db_execute(
        "INSERT INTO agent_devices (api_key, user_email, device_name, created_at) VALUES (?, ?, ?, datetime('now'))",
        (api_key, user_email, "termux"),
    )
    return api_key


def _db_touch_agent(api_key: str) -> None:
    _db_execute(
        "UPDATE agent_devices SET last_seen = datetime('now') WHERE api_key = ?",
        (api_key,),
    )


def _db_get_agent_devices() -> list[dict]:
    user_email = session.get("user_email")
    if user_email:
        return _db_fetchall(
            """
            SELECT api_key, user_email, device_name, created_at, last_seen
            FROM agent_devices
            WHERE user_email = ?
            ORDER BY created_at DESC
            """,
            (user_email,),
        )
    return _db_fetchall(
        """
        SELECT api_key, user_email, device_name, created_at, last_seen
        FROM agent_devices
        ORDER BY created_at DESC
        """
    )


def _db_get_agent_jobs() -> list[dict]:
    user_email = session.get("user_email")
    query = """
        SELECT job_id, api_key, payload, status, created_at
        FROM agent_jobs
        ORDER BY created_at DESC
        LIMIT 200
    """
    params = ()
    if user_email:
        query = """
            SELECT j.job_id, j.api_key, j.payload, j.status, j.created_at
            FROM agent_jobs j
            JOIN agent_devices d ON d.api_key = j.api_key
            WHERE d.user_email = ?
            ORDER BY j.created_at DESC
            LIMIT 200
        """
        params = (user_email,)
    rows = _db_fetchall(query, params)
    for row in rows:
        try:
            payload = json.loads(row.get("payload", "{}"))
        except ValueError:
            payload = {}
        row["targets"] = len(payload.get("targets", []))
        row["mode"] = payload.get("mode", "-")
    return rows


def _db_get_agent_results(limit: int = 200) -> list[dict]:
    user_email = session.get("user_email")
    query = """
        SELECT r.job_id, r.target, r.mode, r.success, r.error, r.created_at
        FROM agent_results r
        ORDER BY r.created_at DESC
        LIMIT ?
    """
    params = (limit,)
    if user_email:
        query = """
            SELECT r.job_id, r.target, r.mode, r.success, r.error, r.created_at
            FROM agent_results r
            JOIN agent_jobs j ON j.job_id = r.job_id
            JOIN agent_devices d ON d.api_key = j.api_key
            WHERE d.user_email = ?
            ORDER BY r.created_at DESC
            LIMIT ?
        """
        params = (user_email, limit)
    return _db_fetchall(query, params)


@app.context_processor
def inject_user():
    return {"current_user": _current_user()}


_init_db()


@app.route("/")
def index():
    return render_template("index.html", active_menu="dashboard")


@app.route("/login")
def login():
    return render_template("auth/login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/agent-status")
def agent_status():
    devices = _db_get_agent_devices()
    jobs = _db_get_agent_jobs()
    results = _db_get_agent_results()
    return render_template(
        "agent_status.html",
        active_menu="agent-status",
        devices=devices,
        jobs=jobs,
        results=results,
    )


@app.route("/auth/google")
def auth_google():
    redirect_uri = url_for("auth_google_callback", _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/auth/google/callback")
def auth_google_callback():
    token = oauth.google.authorize_access_token()
    userinfo = oauth.google.parse_id_token(token)
    if not userinfo:
        return redirect(url_for("login"))
    session["user_email"] = userinfo.get("email")
    session["user_name"] = userinfo.get("name")
    session["user_picture"] = userinfo.get("picture")
    _upsert_user(session["user_email"], session.get("user_name"), session.get("user_picture"))
    return redirect(url_for("tool_page", name="subdomain"))


@app.route("/scan/<mode>", methods=["GET", "POST"])
def scan_mode(mode):
    if mode not in SCAN_MODES:
        abort(404)

    result_payload = None
    if request.method == "POST":
        result_payload = run_xray_scan(
            mode,
            request.form.get("url", "").strip(),
            request.form.get("list_file", "").strip(),
            request.form.get("sni", "").strip(),
            request.form.get("target_domain", "").strip(),
            request.files.get("list_upload"),
            request.form.get("execution_mode", "server"),
        )

    meta = SCAN_MODES[mode]
    return render_template(
        "page_scan.html",
        active_menu=f"scan-{mode}",
        mode=mode,
        mode_title=meta["title"],
        mode_help=meta["help"],
        result_payload=result_payload,
        agent_key=_get_or_create_agent_key() if mode == "auto" else None,
    )


@app.route("/tool/<name>", methods=["GET", "POST"])
def tool_page(name):
    if name not in SIMPLE_PAGES:
        abort(404)

    output_text = None
    error_text = None
    subdomain_payload = None
    scans = []

    if request.method == "POST":
        if name == "subdomain":
            domain = request.form.get("domain", "").strip()
            if not domain:
                error_text = "Domain wajib diisi."
        elif name == "reverse-ip":
            ip_addr = request.form.get("ip_address", "").strip()
            output_text, error_text = _capture_run(revip.reverse_ip, [ip_addr])
        elif name == "keyword-search":
            keyword = request.form.get("keyword", "").strip()
            file_name = request.form.get("output_file", "").strip() or "final_results.txt"
            output_text, error_text = _capture_run(keyword_search.search_by_keyword, [keyword, file_name])
        elif name == "ssh-ws":
            use_saved = _safe_bool(request.form.get("use_saved_accounts"))
            temp_file = None
            account_path = DATA_DIR / "ssh_accounts.json"

            if use_saved:
                accounts = _load_ssh_accounts(account_path)
                if not accounts:
                    error_text = "Tidak ada akun tersimpan. Matikan opsi 'use saved accounts' untuk input manual."
            else:
                host = request.form.get("ssh_host", "").strip()
                port = request.form.get("ssh_port", "").strip() or "22"
                username = request.form.get("ssh_username", "").strip()
                password = request.form.get("ssh_password", "").strip()

                if not host or not username or not password:
                    error_text = "Host, username, dan password wajib diisi."
                else:
                    temp_file = TMP_DIR / "_tmp_ssh_accounts.json"
                    try:
                        port_val = int(port)
                    except ValueError:
                        port_val = 22
                    _write_ssh_accounts(
                        [{"host": host, "port": port_val, "username": username, "password": password}],
                        temp_file,
                    )

            if error_text is None:
                target_mode = request.form.get("target_mode", "single")
                target = request.form.get("target_host", "").strip()
                if not target:
                    if target_mode == "single":
                        error_text = "Target host wajib diisi."
                    else:
                        error_text = "Path list file wajib diisi."

            if error_text is None:
                inputs = []
                inputs.append("y")
                inputs.append("1" if target_mode == "single" else "2")
                inputs.append(target)
                inputs.append(request.form.get("scan_mode", "1"))
                inputs.append("y" if _safe_bool(request.form.get("force_full")) else "n")
                inputs.append("y" if _safe_bool(request.form.get("enable_resolve")) else "n")

                headers_raw = request.form.get("custom_headers", "").strip()
                if headers_raw:
                    inputs.append("y")
                    for line in headers_raw.splitlines():
                        line = line.strip()
                        if line:
                            inputs.append(line)
                    inputs.append("")
                else:
                    inputs.append("n")

                output_text, error_text = _capture_run(ssh_ws.ssh_ws_connection, inputs)

            if temp_file and temp_file.exists():
                try:
                    temp_file.unlink()
                except Exception:
                    pass

    meta = SIMPLE_PAGES[name]
    if name == "subdomain":
        scans = _db_get_scans()
    return render_template(
        "page_simple.html",
        active_menu=name,
        page_key=name,
        page_title=meta["title"],
        page_description=meta["description"],
        output_text=output_text,
        error_text=error_text,
        subdomain_payload=subdomain_payload,
        scans=scans,
    )


@app.route("/tool/subdomain/download")
def download_subdomain():
    fmt = request.args.get("fmt", "txt")
    rows = SUBDOMAIN_STATE.get("rows") or []
    if not rows:
        abort(404)

    if fmt == "csv":
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(["NO", "SUBDOMAIN", "IP/HOSTNAME", "STATUS", "INFRASTRUCTURE/PROVIDER"])
        for row in rows:
            ip_host = f"{row['ip']} ({row['hostname']})" if row["hostname"] != "-" else row["ip"]
            writer.writerow([row["no"], row["subdomain"], ip_host, row["status"], row["provider"]])
        buffer.seek(0)
        return send_file(
            io.BytesIO(buffer.getvalue().encode("utf-8")),
            mimetype="text/csv",
            as_attachment=True,
            download_name="subdomains.csv",
        )

    buffer = io.StringIO()
    for row in rows:
        buffer.write(f"{row['subdomain']}\n")
    buffer.seek(0)
    return send_file(
        io.BytesIO(buffer.getvalue().encode("utf-8")),
        mimetype="text/plain",
        as_attachment=True,
        download_name="subdomains.txt",
    )


@app.route("/tool/subdomain/stream")
def stream_subdomain():
    domain = request.args.get("domain", "").strip()
    scan_id = request.args.get("scan_id", "").strip()
    resume = request.args.get("resume", "0") == "1"
    if not domain:
        abort(400)
    if not scan_id:
        abort(400)

    def generate():
        local_resume = resume
        if local_resume and SUBDOMAIN_STATE["scan_id"] == scan_id:
            SUBDOMAIN_STATE["cancel"] = False
            if not SUBDOMAIN_STATE["subdomains"]:
                local_resume = False

        if not local_resume or SUBDOMAIN_STATE["scan_id"] != scan_id:
            SUBDOMAIN_STATE["scan_id"] = scan_id
            SUBDOMAIN_STATE["domain"] = domain
            SUBDOMAIN_STATE["rows"] = []
            SUBDOMAIN_STATE["subdomains"] = []
            SUBDOMAIN_STATE["index"] = 0
            SUBDOMAIN_STATE["cancel"] = False

            cached_rows = _db_get_cached_rows(domain)
            cached_subdomains = {row["subdomain"] for row in cached_rows if row.get("subdomain")}

            subdomains, error = _fetch_subdomains(domain)
            if error:
                payload = {"message": error}
                yield f"event: error\ndata: {json.dumps(payload)}\n\n"
                return

            merged = sorted(set(subdomains) | cached_subdomains)
            if not merged:
                payload = {"message": "Tidak ada subdomain ditemukan."}
                yield f"event: error\ndata: {json.dumps(payload)}\n\n"
                return

            SUBDOMAIN_STATE["subdomains"] = merged
            _db_insert_scan(scan_id, domain)
            output_path = DATA_DIR / "domain.txt"
            output_path.write_text("\n".join(merged), encoding="utf-8")
            yield f"event: start\ndata: {json.dumps({'total': len(merged), 'output': str(output_path), 'cached': len(cached_subdomains)})}\n\n"

            for cached in cached_rows:
                cached_payload = {
                    "no": 0,
                    "subdomain": cached.get("subdomain", "-"),
                    "ip": cached.get("ip") or "-",
                    "hostname": cached.get("hostname") or "-",
                    "status": cached.get("status") or "-",
                    "provider": cached.get("provider") or "-",
                }
                yield f"event: cached\ndata: {json.dumps(cached_payload)}\n\n"
        else:
            output_path = DATA_DIR / "domain.txt"
            yield f"event: start\ndata: {json.dumps({'total': len(SUBDOMAIN_STATE['subdomains']), 'output': str(output_path), 'resume': True})}\n\n"

        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        with httpx.Client(timeout=5, verify=False, follow_redirects=True) as client:
            total = len(SUBDOMAIN_STATE["subdomains"])
            while SUBDOMAIN_STATE["index"] < total:
                if SUBDOMAIN_STATE["cancel"]:
                    yield "event: stopped\ndata: {}\n\n"
                    return
                idx = SUBDOMAIN_STATE["index"] + 1
                subdomain = SUBDOMAIN_STATE["subdomains"][SUBDOMAIN_STATE["index"]]
                ip, hostname = _resolve_host(subdomain)
                status = "DNS_FAIL"
                provider = hostname or "-"
                if ip:
                    status = "ERR"
                    try:
                        resp = client.get(f"https://{subdomain}", headers=headers)
                    except httpx.RequestError:
                        resp = None
                    if resp is None:
                        try:
                            resp = client.get(f"http://{subdomain}", headers=headers)
                        except httpx.RequestError:
                            resp = None
                    if resp is not None:
                        status = str(resp.status_code)
                        provider = _detect_provider(resp.headers, hostname)

                row = {
                    "no": idx,
                    "subdomain": subdomain,
                    "ip": ip or "-",
                    "hostname": hostname or "-",
                    "status": status,
                    "provider": provider,
                }
                SUBDOMAIN_STATE["rows"].append(row)
                SUBDOMAIN_STATE["index"] += 1
                _db_insert_row(scan_id, row)
                yield f"event: row\ndata: {json.dumps(row)}\n\n"
                yield f"event: progress\ndata: {json.dumps({'current': idx, 'total': total})}\n\n"

        yield "event: done\ndata: {}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache"},
    )


@app.route("/tool/subdomain/stop", methods=["POST"])
def stop_subdomain():
    scan_id = request.form.get("scan_id", "").strip()
    if not scan_id or SUBDOMAIN_STATE["scan_id"] != scan_id:
        abort(404)
    SUBDOMAIN_STATE["cancel"] = True
    return {"status": "stopped"}


@app.route("/tool/subdomain/history")
def subdomain_history():
    scan_id = request.args.get("scan_id", "").strip()
    if not scan_id:
        abort(400)
    rows = _db_get_results(scan_id)
    return {"rows": rows}


@app.route("/api/agent/poll", methods=["POST"])
def agent_poll():
    api_key = request.form.get("api_key", "").strip()
    if not api_key:
        abort(400)
    _db_touch_agent(api_key)
    rows = _db_fetchall(
        "SELECT job_id, payload FROM agent_jobs WHERE api_key = ? AND status = 'pending' ORDER BY created_at ASC LIMIT 1",
        (api_key,),
    )
    if not rows:
        return {"job": None}
    job_id = rows[0]["job_id"]
    _db_execute("UPDATE agent_jobs SET status = 'running' WHERE job_id = ?", (job_id,))
    return {"job": json.loads(rows[0]["payload"])}


@app.route("/api/agent/report", methods=["POST"])
def agent_report():
    api_key = request.form.get("api_key", "").strip()
    job_id = request.form.get("job_id", "").strip()
    results_raw = request.form.get("results", "")
    if not api_key or not job_id:
        abort(400)
    _db_touch_agent(api_key)
    rows = _db_fetchall(
        "SELECT job_id FROM agent_jobs WHERE job_id = ? AND api_key = ?",
        (job_id, api_key),
    )
    if not rows:
        abort(404)
    try:
        results = json.loads(results_raw) if results_raw else []
    except ValueError:
        results = []
    for item in results:
        _db_execute(
            """
            INSERT INTO agent_results (job_id, target, mode, success, error, created_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """,
            (
                job_id,
                item.get("target", "-"),
                item.get("mode", "-"),
                1 if item.get("success") else 0,
                item.get("error"),
            ),
        )
    _db_execute("UPDATE agent_jobs SET status = 'done' WHERE job_id = ?", (job_id,))
    return {"status": "ok"}


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
