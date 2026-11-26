"""
KirimPelanggan — Enterprise Partner Operations Platform.

Runtime     : Streamlit Community Cloud (streamlit.io)
Storage     : S3-compatible (Hugging Face bucket), per-entity JSON
Auth        : PBKDF2-HMAC-SHA256, 120.000 iterasi + HMAC Signed Session

Secret (st.secrets):
    S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET
    S3_REGION          (opsional, default us-east-1)
    ADMIN_PASSWORD
    SESSION_SECRET     (opsional, otomatis diturunkan bila tidak diisi)
"""
import base64
import csv
import hashlib
import hmac
import html as html_lib
import io
import json
import math
import re
import secrets
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st
import streamlit.components.v1 as components
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------- Konfigurasi
st.set_page_config(
    page_title="KirimPelanggan — Platform Kemitraan",
    page_icon="📨",
    layout="centered",
    initial_sidebar_state="collapsed",
)

RATE = 1500
MIN_WD = 10000
DAILY = 1000
PAGE_SIZE = 20
MAX_PROOF_MB = 5
MAX_PROOF_FILES = 10
CLAIM_RETENTION_DAYS = 3
SESSION_TTL = 7 * 86400  # 7 hari
WIB = timezone(timedelta(hours=7))
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


def now_wib() -> datetime:
    return datetime.now(WIB)


def today() -> str:
    return now_wib().strftime("%Y-%m-%d")


def esc(val) -> str:
    return html_lib.escape("" if val is None else str(val), quote=True)


def rp(n) -> str:
    t = f"{float(n):,.2f}"
    return "Rp" + t.replace(",", "X").replace(".", ",").replace("X", ".")


def rp_short(n) -> str:
    return "Rp" + f"{int(n):,}".replace(",", ".")


def badge_html(status: str) -> str:
    s = (status or "").lower()
    mapping = {
        "pending": ("Menunggu", "kp-badge-warn"),
        "disetujui": ("Disetujui", "kp-badge-ok"),
        "dibayar": ("Dibayar", "kp-badge-ok"),
        "ditolak": ("Ditolak", "kp-badge-err"),
        "terkredit": ("Terkredit", "kp-badge-ok"),
        "selesai": ("Selesai", "kp-badge-info"),
        "belum": ("Belum", "kp-badge-muted"),
        "aktif": ("Aktif", "kp-badge-ok"),
        "diblokir": ("Diblokir", "kp-badge-err"),
    }
    label, cls = mapping.get(s, (status.capitalize(), "kp-badge-muted"))
    return f'<span class="kp-badge {cls}">{esc(label)}</span>'


# ---------------------------------------------------------------- Storage S3
@st.cache_resource
def client():
    return boto3.client(
        "s3",
        endpoint_url=st.secrets["S3_ENDPOINT"].strip(),
        aws_access_key_id=st.secrets["S3_ACCESS_KEY"].strip(),
        aws_secret_access_key=st.secrets["S3_SECRET_KEY"].strip(),
        region_name=st.secrets.get("S3_REGION", "us-east-1"),
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )


_raw = st.secrets["S3_BUCKET"].strip().replace("s3://", "").strip("/")
BUCKET, _, _pref = _raw.partition("/")
PREFIX = (_pref.strip("/") + "/") if _pref else ""


def get(key: str, default):
    try:
        body = client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read()
        return json.loads(body)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return default
        raise


def put(key: str, obj):
    client().put_object(
        Bucket=BUCKET,
        Key=PREFIX + key,
        Body=json.dumps(obj, ensure_ascii=False).encode("utf-8"),
        ContentType="application/json",
    )


def delete_key(key: str):
    client().delete_object(Bucket=BUCKET, Key=PREFIX + key)


def get_bytes(key: str):
    try:
        return client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read()
    except ClientError:
        return None


def list_keys(prefix: str) -> list[str]:
    keys = []
    token = None
    full_prefix = PREFIX + prefix
    while True:
        kw = {"Bucket": BUCKET, "Prefix": full_prefix}
        if token:
            kw["ContinuationToken"] = token
        r = client().list_objects_v2(**kw)
        for o in r.get("Contents", []):
            keys.append(o["Key"][len(PREFIX):])
        if not r.get("IsTruncated"):
            break
        token = r["NextContinuationToken"]
    return keys


@st.cache_data(ttl=3600, show_spinner=False)
def cleanup(day: str) -> bool:
    """
    Hapus stok DB lama (di luar hari ini), serta klaim & bukti yang lebih
    lama dari CLAIM_RETENTION_DAYS agar bukti malam hari tetap bisa diverifikasi
    keesokan harinya oleh admin.
    """
    cutoff = (datetime.strptime(day, "%Y-%m-%d") - timedelta(days=CLAIM_RETENTION_DAYS)).strftime("%Y-%m-%d")

    for k in list_keys("db/"):
        parts = k.split("/")
        if len(parts) >= 3 and DATE_RE.match(parts[1]) and parts[1] < day:
            delete_key(k)

    for prefix in ("claims/", "proofs/"):
        for k in list_keys(prefix):
            parts = k.split("/")
            if len(parts) >= 3 and DATE_RE.match(parts[1]) and parts[1] < cutoff:
                delete_key(k)
    return True


@st.cache_data(ttl=86400, show_spinner=False)
def migrate_users_if_needed() -> bool:
    """Migrasi satu kali dari monolithic users.json ke users/{username}.json."""
    marker = get("migrations/users_v2.json", None)
    if marker:
        return True
    legacy = get("users.json", {})
    if legacy:
        existing = set(list_keys("users/"))
        for u, data in legacy.items():
            key = f"users/{u}.json"
            if key not in existing:
                put(key, data)
    put("migrations/users_v2.json", {"done": True, "at": now_wib().isoformat()})
    return True


def user_key(username: str) -> str:
    return f"users/{username.strip().lower()}.json"


def get_user(username: str):
    u = username.strip().lower()
    if not u:
        return None
    return get(user_key(u), None)


def save_user(username: str, data: dict):
    put(user_key(username), data)


def load_all_users() -> dict[str, dict]:
    keys = [k for k in list_keys("users/") if k.endswith(".json")]
    if not keys:
        return {}
    out = {}

    def _fetch(k: str):
        uname = k[len("users/"):-len(".json")]
        data = get(k, None)
        return uname, data

    with ThreadPoolExecutor(max_workers=12) as ex:
        for uname, data in ex.map(_fetch, keys):
            if data is not None:
                out[uname] = data
    return dict(sorted(out.items()))


try:
    client().list_objects_v2(Bucket=BUCKET, Prefix=PREFIX, MaxKeys=1)
except (ClientError, BotoCoreError) as e:
    err = getattr(e, "response", {}).get("Error", {"Code": "?", "Message": str(e)})
    st.error(f"Penyimpanan tidak dapat diakses: {err.get('Code')} — {err.get('Message')}")
    st.stop()

migrate_users_if_needed()
cleanup(today())


# ---------------------------------------------------------------- Parser entri
def parse_db_lines(raw: str) -> list[dict]:
    """Parse 'nomor [nama]' per baris menjadi list of dict."""
    out, seen = [], set()
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        parts = s.split(None, 1)
        nomor = parts[0].strip()
        nama = parts[1].strip() if len(parts) > 1 else ""
        if not nomor or nomor in seen:
            continue
        seen.add(nomor)
        entry = {"nomor": nomor}
        if nama:
            entry["nama"] = nama
        out.append(entry)
    return out


def parse_csv_bytes(content: bytes) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    sample = "\n".join(text.splitlines()[:5])
    delimiter = ","
    for cand in (",", ";", "\t"):
        if cand in sample:
            delimiter = cand
            break
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    out, seen = [], set()
    header_words = {"nomor", "number", "phone", "hp", "no_hp", "no", "telp"}
    for idx, row in enumerate(reader):
        if not row:
            continue
        first = row[0].strip()
        if not first or first.startswith("#"):
            continue
        if idx == 0 and first.lower() in header_words:
            continue
        nama = row[1].strip() if len(row) > 1 else ""
        if first in seen:
            continue
        seen.add(first)
        entry = {"nomor": first}
        if nama:
            entry["nama"] = nama
        out.append(entry)
    return out


def parse_db_file(up) -> list[dict]:
    name = (up.name or "").lower()
    content = up.getvalue()
    if name.endswith(".json"):
        data = json.loads(content)
        if not isinstance(data, list):
            raise ValueError("Root JSON harus array.")
        out = []
        for item in data:
            if isinstance(item, str):
                out.extend(parse_db_lines(item))
            elif isinstance(item, dict) and item:
                out.append(item)
            else:
                raise ValueError(f"Tipe entri tidak didukung: {type(item).__name__}")
        return out
    if name.endswith(".csv"):
        return parse_csv_bytes(content)
    return parse_db_lines(content.decode("utf-8", errors="replace"))


def entry_nomor(d):
    if isinstance(d, dict):
        return d.get("nomor") or d.get("number") or d.get("phone") or d.get("hp")
    return None


def entry_nama(d):
    if isinstance(d, dict):
        return d.get("nama") or d.get("name")
    return None


def fmt_account(acc: dict | None) -> str:
    if not acc:
        return "Belum didaftarkan"
    return f"{acc.get('type', '-')} · {acc.get('number', '-')} · a.n. {acc.get('name', '-')}"


# ---------------------------------------------------------------- Auth & Sesi Persisten
def _session_secret() -> bytes:
    raw = st.secrets.get("SESSION_SECRET") or (
        st.secrets["ADMIN_PASSWORD"] + "|" + st.secrets["S3_SECRET_KEY"]
    )
    return hashlib.sha256(raw.encode()).digest()


def make_session_token(username: str, pw_hash: str, ttl_seconds: int = SESSION_TTL) -> str:
    payload = json.dumps({
        "u": username,
        "v": pw_hash[:8],
        "exp": int(time.time()) + ttl_seconds,
    }, separators=(",", ":")).encode()
    b64 = base64.urlsafe_b64encode(payload).decode().rstrip("=")
    sig = hmac.new(_session_secret(), b64.encode(), hashlib.sha256).hexdigest()[:24]
    return f"{b64}.{sig}"


def verify_session_token(token: str) -> tuple[str, str] | None:
    try:
        b64, sig = token.split(".", 1)
        expected = hmac.new(_session_secret(), b64.encode(), hashlib.sha256).hexdigest()[:24]
        if not hmac.compare_digest(sig, expected):
            return None
        pad = "=" * (-len(b64) % 4)
        data = json.loads(base64.urlsafe_b64decode(b64 + pad))
        if int(data["exp"]) < int(time.time()):
            return None
        return str(data["u"]), str(data["v"])
    except Exception:
        return None


def sync_session():
    """Pulihkan sesi login dari query param token saat tab ter-refresh / kembali dari app lain."""
    if st.session_state.get("user") and st.session_state.get("sid"):
        if st.query_params.get("s") != st.session_state.sid:
            st.query_params["s"] = st.session_state.sid
        return

    tok = st.query_params.get("s")
    if not tok:
        return

    parsed = verify_session_token(tok)
    if not parsed:
        st.query_params.pop("s", None)
        return

    u, ver = parsed
    rec = get_user(u)
    if rec and not rec.get("banned") and rec["pw"][:8] == ver:
        st.session_state.user = u
        st.session_state.sid = tok
    else:
        st.query_params.pop("s", None)


def clear_session():
    st.session_state.pop("user", None)
    st.session_state.pop("sid", None)
    st.session_state.pop("acc_prompted", None)
    st.query_params.pop("s", None)


def hash_pw(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()


def register(username: str, pw: str) -> str | None:
    u = username.strip().lower()
    if not u.isalnum() or len(u) < 4 or len(u) > 24:
        return "Username harus 4–24 karakter (huruf dan angka saja)."
    if len(pw) < 6:
        return "Password minimal 6 karakter."
    if get_user(u) is not None:
        return "Username sudah dipakai."
    salt = secrets.token_hex(16)
    save_user(u, {
        "salt": salt,
        "pw": hash_pw(pw, salt),
        "balance": 0,
        "account": None,
        "banned": False,
        "created": now_wib().isoformat(),
    })
    return None


def login(username: str, pw: str) -> str | None:
    u = username.strip().lower()
    rec = get_user(u)
    if not rec or not secrets.compare_digest(hash_pw(pw, rec["salt"]), rec["pw"]):
        return "Username atau password salah."
    if rec.get("banned"):
        return "Akun diblokir. Hubungi tim operasional."
    tok = make_session_token(u, rec["pw"])
    st.session_state.user = u
    st.session_state.sid = tok
    st.query_params["s"] = tok
    return None


# ---------------------------------------------------------------- Klaim
def claim_key(user: str, day: str | None = None) -> str:
    return f"claims/{day or today()}/{user}.json"


def request_db(user: str, n: int) -> tuple[int, str | None]:
    d = today()
    mine = get(claim_key(user, d), [])
    allow = min(n, DAILY - len(mine))
    if allow <= 0:
        return 0, "Batas klaim harian tercapai."
    pool = get(f"db/{d}/pool.json", [])
    assigned = get(f"db/{d}/assigned.json", {})
    free = [x for x in pool if x["id"] not in assigned][:allow]
    if not free:
        return 0, "Stok entri hari ini sedang habis. Silakan cek kembali nanti."
    for x in free:
        assigned[x["id"]] = user
        mine.append({
            "id": x["id"],
            "data": x["data"],
            "status": False,
            "credited": False,
        })
    put(f"db/{d}/assigned.json", assigned)
    put(claim_key(user, d), mine)
    return len(free), None


# ---------------------------------------------------------------- Komponen UI
def is_dark() -> bool:
    try:
        return st.context.theme.type == "dark"
    except Exception:
        return False


def copy_block(text: str, label: str = "Instruksi & Template Pesan"):
    if not text.strip():
        st.info("Belum ada teks instruksi aktif dari tim operasional.")
        return

    payload = json.dumps(text, ensure_ascii=False).replace("</", "<\\/")
    safe = esc(text)
    lines = text.count("\n") + 1
    height = max(145, min(70 + lines * 22 + 48, 520))

    if is_dark():
        bg, head_bg, fg, border, muted = "#0f172a", "#111c33", "#e2e8f0", "#1e293b", "#94a3b8"
    else:
        bg, head_bg, fg, border, muted = "#ffffff", "#f8fafc", "#0f172a", "#e2e8f0", "#475569"

    components.html(f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;background:transparent;
       font-family:'Inter',-apple-system,system-ui,sans-serif}}
  .wrap{{background:{bg};border:1px solid {border};border-radius:14px;
        overflow:hidden;color:{fg};box-shadow:0 1px 3px rgba(15,23,42,.04)}}
  .head{{display:flex;justify-content:space-between;align-items:center;
        padding:10px 16px;background:{head_bg};border-bottom:1px solid {border};
        font-size:11px;font-weight:600;text-transform:uppercase;
        letter-spacing:.08em;color:{muted}}}
  .btn{{background:{bg};color:{fg};border:1px solid {border};
       border-radius:8px;padding:5px 12px;cursor:pointer;font-size:12px;
       font-weight:600;font-family:inherit;transition:all .15s}}
  .btn:hover{{border-color:#6366f1;color:#6366f1}}
  .btn:active{{transform:scale(.97)}}
  pre{{margin:0;padding:16px 18px;white-space:pre-wrap;word-break:break-word;
      font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;
      line-height:1.65}}
</style></head><body>
<div class="wrap">
  <div class="head"><span>{esc(label)}</span>
    <button class="btn" id="cp" type="button">Salin Teks</button>
  </div>
  <pre>{safe}</pre>
</div>
<script>
  const txt = {payload};
  const btn = document.getElementById('cp');
  btn.addEventListener('click', async () => {{
    try {{
      await navigator.clipboard.writeText(txt);
    }} catch (e) {{
      const ta = document.createElement('textarea');
      ta.value = txt;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }}
    btn.textContent = '✓ Tersalin';
    setTimeout(() => btn.textContent = 'Salin Teks', 1600);
  }});
</script>
</body></html>""", height=height)


@st.dialog("Rekening Tujuan Penarikan")
def account_dialog():
    st.caption("Pastikan nomor rekening atau e-wallet sesuai dengan nama pemilik untuk kelancaran pencairan.")
    user = st.session_state.get("user")
    cur = (get_user(user) or {}).get("account") or {}
    options = ["DANA", "OVO", "GoPay", "ShopeePay", "BCA", "BRI", "BNI", "Mandiri", "Lainnya"]
    idx = options.index(cur["type"]) if cur.get("type") in options else 0
    kind = st.selectbox("Bank / E-Wallet", options, index=idx)
    num = st.text_input("Nomor Rekening / E-Wallet", value=cur.get("number", ""))
    name = st.text_input("Nama Pemilik Sesuai Rekening", value=cur.get("name", ""))
    if st.button("Simpan Rekening", type="primary", use_container_width=True):
        if not num.strip() or not name.strip():
            st.error("Mohon lengkapi semua kolom.")
            return
        fresh = get_user(user)
        if not fresh:
            st.error("Sesi tidak valid.")
            return
        fresh["account"] = {
            "type": kind,
            "number": num.strip(),
            "name": name.strip(),
        }
        save_user(user, fresh)
        st.session_state.acc_prompted = True
        st.rerun()


@st.fragment
def task_list_fragment(user: str, d: str, mine: list[dict]):
    """Fragment terisolasi agar filter, pencarian, dan pagination tidak me-refresh satu halaman penuh."""
    if not mine:
        st.markdown("""
        <div class="kp-empty">
          <div class="kp-empty-title">Belum ada tugas diambil hari ini</div>
          <div class="kp-empty-sub">Gunakan formulir di atas untuk mengambil entri pelanggan dari stok harian.</div>
        </div>
        """, unsafe_allow_html=True)
        return

    f1, f2 = st.columns([1.4, 2])
    filt = f1.selectbox(
        "Filter status",
        ["Semua", "Belum selesai", "Selesai (belum kredit)", "Sudah dikredit"],
        label_visibility="collapsed",
    )
    q = f2.text_input(
        "Cari nomor atau nama",
        placeholder="Cari nomor atau nama...",
        label_visibility="collapsed",
    ).strip().lower()

    indexed = list(enumerate(mine))
    if filt == "Belum selesai":
        indexed = [(i, x) for i, x in indexed if not x["status"]]
    elif filt == "Selesai (belum kredit)":
        indexed = [(i, x) for i, x in indexed if x["status"] and not x["credited"]]
    elif filt == "Sudah dikredit":
        indexed = [(i, x) for i, x in indexed if x["credited"]]

    if q:
        indexed = [
            (i, x) for i, x in indexed
            if q in (str(entry_nomor(x["data"]) or "")).lower()
            or q in (str(entry_nama(x["data"]) or "")).lower()
        ]

    total_filtered = len(indexed)
    total_pages = max(1, math.ceil(total_filtered / PAGE_SIZE))
    page_key = "task_page_num"
    if page_key in st.session_state and st.session_state[page_key] > total_pages:
        st.session_state[page_key] = total_pages
    if page_key not in st.session_state:
        st.session_state[page_key] = 1

    p_col1, p_col2, p_col3 = st.columns([1.4, 1.4, 1.8], vertical_alignment="center")
    p_col1.caption(f"Menampilkan {total_filtered} dari {len(mine)} entri")
    if total_pages > 1:
        cur_page = int(p_col2.number_input(
            "Halaman", min_value=1, max_value=total_pages, step=1,
            label_visibility="collapsed", key=page_key,
        ))
    else:
        cur_page = 1
        p_col2.caption("Halaman 1 / 1")

    start = (cur_page - 1) * PAGE_SIZE
    page_items = indexed[start:start + PAGE_SIZE]

    if p_col3.button("Tandai Halaman Ini Selesai", use_container_width=True, disabled=not page_items):
        fresh_mine = get(claim_key(user, d), [])
        changed_bulk = False
        for idx, _ in page_items:
            if idx < len(fresh_mine) and not fresh_mine[idx]["credited"] and not fresh_mine[idx]["status"]:
                fresh_mine[idx]["status"] = True
                changed_bulk = True
        if changed_bulk:
            put(claim_key(user, d), fresh_mine)
            st.rerun()

    if not page_items:
        st.caption("Tidak ada entri yang cocok dengan filter.")
        return

    with st.form("tasks_batch_form"):
        new_vals = {}
        for pos, (idx, item) in enumerate(page_items):
            nomor = entry_nomor(item["data"])
            nama = entry_nama(item["data"])
            row_l, row_m, row_r = st.columns([2.6, 1.2, 1], vertical_alignment="center")
            if nomor:
                row_l.code(str(nomor), language=None)
                if nama:
                    row_l.caption(str(nama))
            else:
                row_l.code(json.dumps(item["data"], ensure_ascii=False), language=None)

            if item["credited"]:
                row_m.markdown(badge_html("terkredit"), unsafe_allow_html=True)
            elif item["status"]:
                row_m.markdown(badge_html("selesai"), unsafe_allow_html=True)
            else:
                row_m.markdown(badge_html("belum"), unsafe_allow_html=True)

            new_vals[idx] = row_r.checkbox(
                "Selesai",
                value=item["status"],
                key=f"chk_{d}_{item['id']}",
                disabled=item["credited"],
            )
            if pos < len(page_items) - 1:
                st.markdown('<div class="kp-row-sep"></div>', unsafe_allow_html=True)

        save_tasks = st.form_submit_button(
            "Simpan Perubahan Status", type="primary", use_container_width=True
        )
    if save_tasks:
        fresh_mine = get(claim_key(user, d), [])
        changed = False
        for idx, val in new_vals.items():
            if idx < len(fresh_mine) and not fresh_mine[idx]["credited"] and fresh_mine[idx]["status"] != val:
                fresh_mine[idx]["status"] = val
                changed = True
        if changed:
            put(claim_key(user, d), fresh_mine)
            st.success("Status pekerjaan disimpan.")
            st.rerun()
        else:
            st.info("Tidak ada perubahan status.")


# ---------------------------------------------------------------- Halaman User
def user_page():
    if not st.session_state.get("user"):
        st.switch_page(P_AUTH)
    user = st.session_state.user
    me = get_user(user)
    if not me or me.get("banned"):
        clear_session()
        st.switch_page(P_AUTH)

    if not me.get("account") and not st.session_state.get("acc_prompted"):
        st.session_state.acc_prompted = True
        account_dialog()

    top = st.columns([4, 1.2], vertical_alignment="center")
    status_pill = badge_html("aktif") if me.get("account") else '<span class="kp-badge kp-badge-warn">Rekening Belum Diisi</span>'
    top[0].markdown(
        f'<div class="kp-nav-anchor kp-user-head">'
        f'  <div class="kp-avatar">{esc(user[:2].upper())}</div>'
        f'  <div>'
        f'    <div class="kp-eyebrow">Mitra Terdaftar</div>'
        f'    <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">'
        f'      <span style="font-size:1.15rem;font-weight:700;">@{esc(user)}</span>'
        f'      {status_pill}'
        f'    </div>'
        f'  </div>'
        f'</div>',
        unsafe_allow_html=True,
    )
    if top[1].button("Keluar", use_container_width=True):
        clear_session()
        st.switch_page(P_HOME)

    if not me.get("account"):
        st.warning("Lengkapi rekening bank atau e-wallet terlebih dahulu agar Anda dapat melakukan penarikan saldo.")
        if st.button("Daftarkan Rekening Sekarang", type="primary"):
            account_dialog()

    acc = me.get("account")
    acc_line = (
        f"{esc(acc['type'])} · {esc(acc['number'])} ({esc(acc['name'])})"
        if acc else "Belum ada rekening tujuan"
    )
    st.markdown(f"""
    <div class="kp-balance">
      <div class="kp-balance-top">
        <div>
          <div class="kp-balance-label">Saldo Tersedia</div>
          <div class="kp-balance-value">{rp(me['balance'])}</div>
        </div>
        <div class="kp-balance-chip">{acc_line}</div>
      </div>
      <div class="kp-balance-meta">
        Minimal penarikan {rp_short(MIN_WD)} · Tarif komisi {rp_short(RATE)} per entri terverifikasi
      </div>
    </div>
    """, unsafe_allow_html=True)

    d = today()
    mine = get(claim_key(user, d), [])
    done = sum(1 for x in mine if x["status"])
    pending_verif = sum(1 for x in mine if x["status"] and not x["credited"])
    est_pending = pending_verif * RATE

    st.markdown(f"""
    <div class="kp-kpi-grid kp-kpi-4">
      <div class="kp-stat">
        <div class="kp-stat-v">{len(mine)}/{DAILY}</div>
        <div class="kp-stat-l">Klaim Hari Ini</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{done}</div>
        <div class="kp-stat-l">Tandai Selesai</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{pending_verif}</div>
        <div class="kp-stat-l">Menunggu Verif</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{rp_short(est_pending)}</div>
        <div class="kp-stat-l">Potensi Masuk</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.write("")
    tab_kerja, tab_wd = st.tabs(["Ruang Kerja", "Penarikan & Rekening"])

    # ----- Tab Ruang Kerja -----
    with tab_kerja:
        st.markdown('<div class="kp-section-label">1 · Instruksi Operasional</div>', unsafe_allow_html=True)
        text = get("settings.json", {"text": ""}).get("text", "")
        copy_block(text, "Teks Panduan dari Admin")

        st.markdown('<div class="kp-section-label">2 · Ambil Antrean Tugas</div>', unsafe_allow_html=True)
        remaining_quota = DAILY - len(mine)
        if remaining_quota <= 0:
            st.info(f"Kuota harian Anda sudah penuh ({DAILY}/{DAILY} entri). Reset otomatis pada 00.00 WIB.")
        else:
            with st.form("claim_form"):
                c1, c2 = st.columns([3, 1.3], vertical_alignment="bottom")
                n = c1.number_input(
                    f"Jumlah entri baru (sisa kuota hari ini: {remaining_quota})",
                    min_value=1,
                    max_value=remaining_quota,
                    value=min(10, remaining_quota),
                    step=1,
                )
                submit = c2.form_submit_button("Ambil Tugas", type="primary", use_container_width=True)
            if submit:
                with st.spinner("Mengalokasikan entri eksklusif..."):
                    got, err = request_db(user, int(n))
                if err:
                    st.warning(err)
                else:
                    st.success(f"{got} entri baru berhasil ditambahkan ke daftar Anda.")
                    st.rerun()

        st.markdown('<div class="kp-section-label">3 · Daftar Tugas Pelanggan</div>', unsafe_allow_html=True)
        task_list_fragment(user, d, mine)

        st.markdown('<div class="kp-section-label">4 · Unggah Bukti Pengerjaan</div>', unsafe_allow_html=True)
        if pending_verif == 0:
            st.caption("Tandai minimal 1 entri berstatus **Selesai** di atas sebelum mengirim bukti.")
        else:
            st.caption(f"Anda memiliki **{pending_verif} entri selesai** ({rp_short(est_pending)}) yang siap diverifikasi.")

        files = st.file_uploader(
            f"Pilih screenshot bukti (PNG/JPG/WEBP, maks {MAX_PROOF_MB} MB per file)",
            type=["png", "jpg", "jpeg", "webp"],
            accept_multiple_files=True,
            label_visibility="collapsed",
        )
        if st.button(
            "Kirim Bukti untuk Verifikasi",
            type="primary",
            disabled=(not files or pending_verif == 0),
            use_container_width=True,
        ):
            if len(files) > MAX_PROOF_FILES:
                st.error(f"Maksimal {MAX_PROOF_FILES} file dalam satu pengiriman.")
            else:
                oversized = [f.name for f in files if len(f.getvalue()) > MAX_PROOF_MB * 1024 * 1024]
                if oversized:
                    st.error(f"Ukuran file melebihi {MAX_PROOF_MB} MB: {', '.join(oversized)}")
                else:
                    proofs = get("proofs.json", [])
                    for f in files:
                        ext = f.name.rsplit(".", 1)[-1].lower()
                        key = f"proofs/{d}/{user}-{uuid.uuid4().hex[:8]}.{ext}"
                        client().put_object(Bucket=BUCKET, Key=PREFIX + key, Body=f.getvalue())
                        proofs.append({
                            "id": uuid.uuid4().hex,
                            "user": user,
                            "date": d,
                            "key": key,
                            "claimed_count": pending_verif,
                            "status": "pending",
                            "time": now_wib().isoformat(),
                        })
                    put("proofs.json", proofs)
                    st.success("Bukti berhasil dikirim. Tim verifikasi akan meninjau dalam 15 menit – 12 jam.")
                    st.rerun()

        my_proofs = [p for p in get("proofs.json", []) if p["user"] == user][-5:]
        if my_proofs:
            st.markdown('<div class="kp-section-label">Riwayat Pengiriman Bukti</div>', unsafe_allow_html=True)
            for p in reversed(my_proofs):
                cnt = p.get("claimed_count", "-")
                st.markdown(
                    f'<div class="kp-hist-row">'
                    f'  <div><span class="kp-mono">{esc(p["time"][:16].replace("T", " "))}</span> · '
                    f'  <span style="font-size:.88rem;">Klaim {esc(cnt)} entri</span></div>'
                    f'  <div>{badge_html(p["status"])}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    # ----- Tab Penarikan & Rekening -----
    with tab_wd:
        st.markdown('<div class="kp-section-label">Rekening Tujuan Pencairan</div>', unsafe_allow_html=True)
        if acc:
            st.markdown(f"""
            <div class="kp-callout">
              <div class="kp-callout-title">{esc(acc['type'])} · <span class="kp-mono">{esc(acc['number'])}</span></div>
              <div class="kp-muted">Atas nama: <b>{esc(acc['name'])}</b></div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.caption("Rekening penarikan belum didaftarkan.")
        if st.button("Ubah Rekening Tujuan"):
            account_dialog()

        st.markdown('<div class="kp-section-label">Ajukan Penarikan Dana</div>', unsafe_allow_html=True)
        cur_bal = int(me["balance"])
        if cur_bal < MIN_WD:
            st.info(f"Saldo Anda saat ini {rp(cur_bal)}. Minimal penarikan adalah {rp_short(MIN_WD)}.")
        elif not acc:
            st.warning("Daftarkan rekening terlebih dahulu sebelum mengajukan penarikan.")
        else:
            with st.form("wd_form"):
                amt = st.number_input(
                    f"Nominal penarikan (tersedia: {rp_short(cur_bal)})",
                    min_value=MIN_WD,
                    max_value=cur_bal,
                    step=1000,
                    value=cur_bal,
                )
                submit = st.form_submit_button("Ajukan Penarikan", type="primary", use_container_width=True)
            if submit:
                fresh = get_user(user)
                if not fresh or fresh.get("banned"):
                    st.error("Akun tidak aktif.")
                elif int(amt) > int(fresh["balance"]):
                    st.error("Saldo tidak mencukupi.")
                elif not fresh.get("account"):
                    st.error("Daftarkan rekening terlebih dahulu.")
                else:
                    fresh["balance"] = int(fresh["balance"]) - int(amt)
                    save_user(user, fresh)
                    wd = get("wd.json", [])
                    wd.append({
                        "id": uuid.uuid4().hex,
                        "user": user,
                        "amount": int(amt),
                        "account": fresh["account"],
                        "status": "pending",
                        "time": now_wib().isoformat(),
                    })
                    put("wd.json", wd)
                    st.success("Pengajuan penarikan berhasil dikirim dan sedang diproses tim keuangan.")
                    st.rerun()

        my_wd = [w for w in get("wd.json", []) if w["user"] == user][-10:]
        if my_wd:
            st.markdown('<div class="kp-section-label">Riwayat Penarikan</div>', unsafe_allow_html=True)
            for w in reversed(my_wd):
                w_acc = w.get("account") or {}
                st.markdown(
                    f'<div class="kp-hist-row">'
                    f'  <div>'
                    f'    <div style="font-weight:600;">{rp(w["amount"])}</div>'
                    f'    <div class="kp-muted" style="font-size:.8rem;">'
                    f'      <span class="kp-mono">{esc(w["time"][:16].replace("T", " "))}</span> · '
                    f'      {esc(w_acc.get("type", ""))} {esc(w_acc.get("number", ""))}'
                    f'    </div>'
                    f'  </div>'
                    f'  <div>{badge_html(w["status"])}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )


# ---------------------------------------------------------------- Admin Console
def admin_page():
    if not st.session_state.get("admin"):
        st.markdown("""
        <div style="margin:12px 0 24px;">
          <div class="kp-eyebrow">Internal Operations</div>
          <h1 style="font-size:1.85rem;font-weight:700;letter-spacing:-.025em;margin:4px 0 6px;">Admin Console</h1>
          <p class="kp-muted" style="margin:0;font-size:.94rem;">Akses terbatas untuk tim operasional dan verifikasi.</p>
        </div>
        """, unsafe_allow_html=True)
        tries = st.session_state.get("admin_tries", 0)
        with st.form("admin_login"):
            p = st.text_input("Password Administrator", type="password")
            ok = st.form_submit_button("Masuk Console", type="primary", use_container_width=True)
        if ok:
            if tries >= 5:
                st.error("Terlalu banyak percobaan gagal. Muat ulang halaman.")
            elif secrets.compare_digest(p.encode(), st.secrets["ADMIN_PASSWORD"].encode()):
                st.session_state.admin = True
                st.session_state.admin_tries = 0
                st.rerun()
            else:
                st.session_state.admin_tries = tries + 1
                st.error("Password administrator tidak sesuai.")
        return

    top = st.columns([4, 1.2], vertical_alignment="center")
    top[0].markdown(
        '<div class="kp-nav-anchor"><div class="kp-eyebrow">Internal Operations</div>'
        '<div style="font-size:1.3rem;font-weight:700;">Admin Console</div></div>',
        unsafe_allow_html=True,
    )
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("admin", None)
        st.rerun()

    d = today()
    users = load_all_users()
    wd = get("wd.json", [])
    proofs = get("proofs.json", [])
    pool = get(f"db/{d}/pool.json", [])
    assigned = get(f"db/{d}/assigned.json", {})

    pending_wd = [w for w in wd if w["status"] == "pending"]
    pending_wd_sum = sum(int(w["amount"]) for w in pending_wd)
    pending_proofs = [p for p in proofs if p["status"] == "pending"]

    st.markdown(f"""
    <div class="kp-kpi-grid kp-kpi-4" style="margin:12px 0 18px;">
      <div class="kp-stat">
        <div class="kp-stat-v">{len(users)}</div>
        <div class="kp-stat-l">Total Mitra</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{len(pending_wd)}</div>
        <div class="kp-stat-l">WD Pending ({rp_short(pending_wd_sum)})</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{len(pending_proofs)}</div>
        <div class="kp-stat-l">Bukti Menunggu</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{len(pool) - len(assigned)}/{len(pool)}</div>
        <div class="kp-stat-l">Sisa Stok DB</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    t_db, t_user, t_wd, t_up, t_set, t_home = st.tabs(
        ["Stok DB", "Mitra", "Penarikan", "Verifikasi Bukti", "Instruksi", "Beranda & Lisensi"]
    )

    # ----- Stok DB -----
    with t_db:
        if "db_flash" in st.session_state:
            st.success(st.session_state.pop("db_flash"))

        st.caption(
            f"Periode aktif **{d} (WIB)** · Total {len(pool)} · Terpakai {len(assigned)} · Tersedia {len(pool) - len(assigned)}"
        )

        src = st.radio("Metode input", ["Input Teks", "Unggah File (.txt / .csv / .json)"], horizontal=True)
        raw = ""
        up = None
        if src == "Input Teks":
            st.caption("Format: satu entri per baris (`nomor` atau `nomor<spasi>nama`). Baris `#` diabaikan.")
            raw = st.text_area(
                "Daftar entri",
                height=200,
                placeholder="081234567890 Budi\n081234567891\n081234567892 Siti",
                label_visibility="collapsed",
            )
        else:
            up = st.file_uploader("Pilih file .txt, .csv, atau .json", type=["txt", "csv", "json"], key="db_up")

        if st.button("Tambahkan ke Stok Hari Ini", type="primary"):
            entries = None
            if src == "Input Teks":
                if raw.strip():
                    entries = parse_db_lines(raw)
                else:
                    st.warning("Tempel data entri terlebih dahulu.")
            else:
                if up is not None:
                    try:
                        entries = parse_db_file(up)
                    except Exception as e:
                        st.error(f"File tidak valid: {e}")
                else:
                    st.warning("Unggah file terlebih dahulu.")

            if entries is not None:
                if not entries:
                    st.warning("Tidak ada entri valid yang ditemukan.")
                else:
                    fresh_pool = get(f"db/{d}/pool.json", [])
                    existing_nomor = {entry_nomor(x["data"]) for x in fresh_pool if entry_nomor(x["data"])}
                    existing_json = {json.dumps(x["data"], sort_keys=True) for x in fresh_pool}
                    added = skipped = 0
                    for e in entries:
                        n = entry_nomor(e)
                        key = json.dumps(e, sort_keys=True)
                        if (n and n in existing_nomor) or key in existing_json:
                            skipped += 1
                            continue
                        if n:
                            existing_nomor.add(n)
                        existing_json.add(key)
                        fresh_pool.append({"id": uuid.uuid4().hex[:12], "data": e})
                        added += 1
                    put(f"db/{d}/pool.json", fresh_pool)
                    msg = f"{added} entri berhasil ditambahkan ke stok {d}"
                    if skipped:
                        msg += f" ({skipped} duplikat dilewati)"
                    st.session_state.db_flash = msg
                    st.rerun()

        if assigned:
            st.divider()
            by_user = {}
            for _, uname in assigned.items():
                by_user[uname] = by_user.get(uname, 0) + 1
            st.caption("Distribusi klaim hari ini: " + ", ".join(f"@{u} ({c})" for u, c in sorted(by_user.items())))

    # ----- Mitra -----
    with t_user:
        if not users:
            st.caption("Belum ada mitra terdaftar.")
        else:
            q_u = st.text_input("Cari username", placeholder="Ketik username mitra...")
            filtered_users = {
                u: v for u, v in users.items()
                if not q_u.strip() or q_u.strip().lower() in u
            }
            rows = [
                {
                    "Username": f"@{u}",
                    "Saldo": rp_short(v.get("balance", 0)),
                    "Rekening": fmt_account(v.get("account")),
                    "Status": "Diblokir" if v.get("banned") else "Aktif",
                    "Terdaftar": v.get("created", "")[:10],
                }
                for u, v in filtered_users.items()
            ]
            st.dataframe(rows, use_container_width=True, hide_index=True)

            if filtered_users:
                st.markdown('<div class="kp-section-label">Kelola Akun Mitra</div>', unsafe_allow_html=True)
                sel = st.selectbox("Pilih mitra", list(filtered_users.keys()), format_func=lambda x: f"@{x}")
                v = users[sel]
                claims_today = get(claim_key(sel, d), [])
                done_today = sum(1 for x in claims_today if x["status"])
                with st.container(border=True):
                    st.write(f"**@{sel}** · Terdaftar `{v.get('created', '')[:16].replace('T', ' ')}`")
                    st.write(f"Rekening: {fmt_account(v.get('account'))}")
                    st.write(f"Aktivitas hari ini: Klaim **{len(claims_today)}**, Selesai **{done_today}**")

                    c1, c2, c3 = st.columns([1.4, 1, 1], vertical_alignment="bottom")
                    nb = c1.number_input("Saldo (Rp)", value=int(v.get("balance", 0)), step=1500, key=f"nb_{sel}")
                    if c1.button("Simpan Saldo", key=f"sv_{sel}", type="primary", use_container_width=True):
                        fresh = get_user(sel)
                        if fresh:
                            fresh["balance"] = int(nb)
                            save_user(sel, fresh)
                            st.rerun()

                    ban_label = "Buka Blokir" if v.get("banned") else "Blokir Akun"
                    if c2.button(ban_label, key=f"bn_{sel}", use_container_width=True):
                        fresh = get_user(sel)
                        if fresh:
                            fresh["banned"] = not fresh.get("banned", False)
                            save_user(sel, fresh)
                            st.rerun()

                    if c3.button("Hapus Akun", key=f"dl_{sel}", use_container_width=True):
                        delete_key(user_key(sel))
                        st.rerun()

    # ----- Penarikan -----
    with t_wd:
        if not pending_wd:
            st.info("Tidak ada permintaan penarikan yang menunggu.")
        for w in reversed(pending_wd):
            a = w.get("account") or {}
            with st.container(border=True):
                st.write(f"**@{w['user']}** · **{rp(w['amount'])}**")
                st.caption(
                    f"{a.get('type', '-')} · {a.get('number', '-')} · a.n. {a.get('name', '-')} · "
                    f"Diajukan {w['time'][:16].replace('T', ' ')}"
                )
                c = st.columns(2)
                if c[0].button("Tandai Sudah Dibayar", key=f"p_{w['id']}", type="primary", use_container_width=True):
                    fresh_wd = get("wd.json", [])
                    for item in fresh_wd:
                        if item["id"] == w["id"] and item["status"] == "pending":
                            item["status"] = "dibayar"
                            item["processed_at"] = now_wib().isoformat()
                    put("wd.json", fresh_wd)
                    st.rerun()
                if c[1].button("Tolak & Kembalikan Saldo", key=f"r_{w['id']}", use_container_width=True):
                    fresh_wd = get("wd.json", [])
                    refunded = False
                    for item in fresh_wd:
                        if item["id"] == w["id"] and item["status"] == "pending":
                            item["status"] = "ditolak"
                            item["processed_at"] = now_wib().isoformat()
                            refunded = True
                    if refunded:
                        fresh_u = get_user(w["user"])
                        if fresh_u:
                            fresh_u["balance"] = int(fresh_u["balance"]) + int(w["amount"])
                            save_user(w["user"], fresh_u)
                        put("wd.json", fresh_wd)
                    st.rerun()

        done_wd = [w for w in wd if w["status"] != "pending"]
        if done_wd:
            st.markdown('<div class="kp-section-label">Riwayat Terakhir</div>', unsafe_allow_html=True)
            buf = io.StringIO()
            writer = csv.writer(buf)
            writer.writerow(["Waktu", "Username", "Nominal", "Bank/E-Wallet", "Nomor", "Atas Nama", "Status"])
            for w in reversed(done_wd):
                a = w.get("account") or {}
                writer.writerow([w["time"][:19], w["user"], w["amount"], a.get("type", ""), a.get("number", ""), a.get("name", ""), w["status"]])
            st.download_button(
                "Unduh Riwayat Penarikan (.csv)",
                data=buf.getvalue().encode("utf-8"),
                file_name=f"riwayat-penarikan-{d}.csv",
                mime="text/csv",
            )
            for w in reversed(done_wd[-10:]):
                st.markdown(
                    f'<div class="kp-hist-row">'
                    f'  <div>@{esc(w["user"])} · <b>{rp(w["amount"])}</b> '
                    f'  <span class="kp-muted kp-mono" style="font-size:.8rem;">{esc(w["time"][:16].replace("T", " "))}</span></div>'
                    f'  <div>{badge_html(w["status"])}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

    # ----- Bukti -----
    with t_up:
        if not pending_proofs:
            st.info("Tidak ada bukti pengerjaan yang menunggu verifikasi.")
        for p in reversed(pending_proofs):
            with st.container(border=True):
                cnt = p.get("claimed_count", "-")
                st.write(f"**@{p['user']}** · Tanggal `{p['date']}` · Klaim **{cnt} entri** selesai")
                img = get_bytes(p["key"])
                if img:
                    st.image(img, width=360)
                else:
                    st.caption("Lampiran gambar tidak ditemukan di penyimpanan.")
                c = st.columns(2)
                if c[0].button("Setujui & Kreditkan Saldo", key=f"a_{p['id']}", type="primary", use_container_width=True):
                    claims = get(claim_key(p["user"], p["date"]), [])
                    n = 0
                    for x in claims:
                        if x["status"] and not x["credited"]:
                            x["credited"] = True
                            n += 1
                    if n:
                        fresh_u = get_user(p["user"])
                        if fresh_u:
                            fresh_u["balance"] = int(fresh_u["balance"]) + n * RATE
                            save_user(p["user"], fresh_u)
                        put(claim_key(p["user"], p["date"]), claims)
                    fresh_proofs = get("proofs.json", [])
                    for item in fresh_proofs:
                        if item["id"] == p["id"]:
                            item["status"] = "disetujui"
                            item["credited_entries"] = n
                    put("proofs.json", fresh_proofs)
                    st.rerun()
                if c[1].button("Tolak Bukti", key=f"x_{p['id']}", use_container_width=True):
                    fresh_proofs = get("proofs.json", [])
                    for item in fresh_proofs:
                        if item["id"] == p["id"]:
                            item["status"] = "ditolak"
                    put("proofs.json", fresh_proofs)
                    st.rerun()

        st.caption(
            f"Statistik total: Disetujui {sum(1 for p in proofs if p['status'] == 'disetujui')} · "
            f"Ditolak {sum(1 for p in proofs if p['status'] == 'ditolak')}"
        )

    # ----- Instruksi -----
    with t_set:
        cfg = get("settings.json", {"text": ""})
        txt = st.text_area("Teks instruksi & template pesan untuk mitra", value=cfg.get("text", ""), height=220)
        if st.button("Simpan Instruksi", type="primary"):
            cfg["text"] = txt
            put("settings.json", cfg)
            st.success("Instruksi berhasil diperbarui.")

    # ----- Beranda -----
    with t_home:
        cfg = get("settings.json", {"text": ""})
        lic = st.text_area(
            "Lisensi, Legalitas & Ketentuan Tambahan (Markdown, tampil di halaman Beranda)",
            value=cfg.get("license", ""),
            height=280,
        )
        if st.button("Simpan Konten Beranda", type="primary"):
            cfg["license"] = lic
            put("settings.json", cfg)
            st.success("Konten beranda berhasil disimpan.")


# ---------------------------------------------------------------- Design System CSS
def inject_css():
    muted_color = "#94a3b8" if is_dark() else "#475569"
    st.markdown(f"""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');

:root {{
  --kp-accent: #4f46e5;
  --kp-accent-soft: rgba(79, 70, 229, 0.12);
  --kp-border: rgba(148, 163, 184, 0.24);
  --kp-surface: var(--secondary-background-color, rgba(148, 163, 184, 0.08));
  --kp-muted: {muted_color};
}}

/* Hilangkan tampilan bawaan Streamlit agar tampil seperti web biasa */
header[data-testid="stHeader"],
[data-testid="stToolbar"],
[data-testid="stDecoration"],
[data-testid="stStatusWidget"],
#MainMenu,
footer {{
  display: none !important;
  visibility: hidden !important;
}}

html, body, [class*="css"], .stApp {{
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  font-feature-settings: 'cv11', 'ss01';
  -webkit-font-smoothing: antialiased;
}}

.block-container {{
  max-width: 820px;
  padding-top: 1.5rem;
  padding-bottom: 4rem;
}}

h1 {{ font-weight: 700; letter-spacing: -0.025em; }}
h2 {{ font-weight: 600; letter-spacing: -0.02em; }}
h3 {{ font-weight: 600; letter-spacing: -0.015em; }}
p  {{ line-height: 1.65; }}

code, pre, .kp-mono {{
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace !important;
  font-variant-numeric: tabular-nums;
}}

.kp-muted {{ color: var(--kp-muted); }}
.kp-eyebrow {{
  font-size: .72rem; font-weight: 700; letter-spacing: .09em;
  text-transform: uppercase; color: var(--kp-muted);
}}

.stButton > button, .stFormSubmitButton > button {{
  border-radius: 10px; font-weight: 600; transition: all .15s ease;
}}
[data-testid="stVerticalBlockBorderWrapper"] {{
  border-radius: 14px !important;
  border-color: var(--kp-border) !important;
}}
.stTextInput input, .stNumberInput input, .stTextArea textarea {{
  border-radius: 10px !important;
}}
[data-testid="stFileUploader"] section {{
  border-radius: 12px; border-style: dashed !important;
}}

[data-testid="stHorizontalBlock"]:has(.kp-nav-anchor) {{
  flex-direction: row !important;
  flex-wrap: nowrap !important;
  align-items: center !important;
  gap: 8px !important;
}}
[data-testid="stHorizontalBlock"]:has(.kp-nav-anchor) > div {{
  min-width: 0 !important;
}}
a[data-testid="stPageLink-NavLink"] {{
  padding: 7px 12px !important;
  border-radius: 9px !important;
  text-decoration: none !important;
  font-weight: 600 !important;
  font-size: .88rem !important;
  border: 1px solid var(--kp-border) !important;
  justify-content: center !important;
  transition: all .15s ease !important;
}}
a[data-testid="stPageLink-NavLink"]:hover {{
  border-color: #6366f1 !important;
  background: var(--kp-accent-soft) !important;
}}

.kp-brand {{
  display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 1.02rem; letter-spacing: -0.02em;
}}
.kp-brand-mark {{
  width: 28px; height: 28px; border-radius: 8px;
  background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
  display: inline-flex; align-items: center; justify-content: center;
  color: #fff; font-size: .8rem; font-weight: 800;
  box-shadow: 0 4px 12px rgba(79, 70, 229, 0.28);
  flex-shrink: 0;
}}
.kp-brand-sub {{
  font-size: .68rem; font-weight: 600; color: var(--kp-muted);
  text-transform: uppercase; letter-spacing: .08em; display: block;
  margin-top: -2px;
}}
.kp-nav-divider {{
  height: 1px; background: var(--kp-border); margin: 10px 0 22px;
}}

.kp-hero {{
  position: relative;
  background:
    radial-gradient(circle at 95% 5%, rgba(99,102,241,0.30), transparent 52%),
    radial-gradient(circle at 10% 90%, rgba(16,185,129,0.10), transparent 45%),
    linear-gradient(180deg, #090f1d 0%, #0f172a 100%);
  color: #e2e8f0;
  border-radius: 22px;
  padding: 40px 34px 36px;
  margin: 4px 0 18px;
  border: 1px solid rgba(148,163,184,0.16);
  box-shadow: 0 18px 40px -18px rgba(15, 23, 42, 0.45);
}}
.kp-hero-top {{
  display: flex; align-items: center; justify-content: space-between;
  flex-wrap: wrap; gap: 10px; margin-bottom: 20px;
}}
.kp-hero-badge {{
  display: inline-flex; align-items: center; gap: 7px;
  font-size: .72rem; font-weight: 600; letter-spacing: .08em;
  text-transform: uppercase; color: #cbd5e1;
  background: rgba(148,163,184,0.1);
  border: 1px solid rgba(148,163,184,0.22); border-radius: 999px;
  padding: 5px 12px;
}}
.kp-pulse {{
  width: 7px; height: 7px; border-radius: 50%; background: #22c55e;
  box-shadow: 0 0 0 3px rgba(34, 197, 94, 0.25);
}}
.kp-hero h1 {{
  font-size: 2.2rem; font-weight: 800; line-height: 1.15;
  margin: 0 0 14px; color: #f8fafc; letter-spacing: -.03em;
}}
.kp-hero p {{
  font-size: 1rem; line-height: 1.65; color: #94a3b8;
  margin: 0; max-width: 560px;
}}

.kp-kpi-grid {{ display: grid; gap: 12px; margin: 14px 0 4px; }}
.kp-kpi-3 {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
.kp-kpi-4 {{ grid-template-columns: repeat(4, minmax(0, 1fr)); }}
@media (max-width: 640px) {{
  .kp-kpi-3, .kp-kpi-4 {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
  .kp-hero {{ padding: 28px 22px; }}
  .kp-hero h1 {{ font-size: 1.65rem; }}
}}

.kp-stat {{
  background: var(--kp-surface);
  border: 1px solid var(--kp-border);
  border-radius: 14px; padding: 15px 16px;
}}
.kp-stat-v {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.15rem; font-weight: 700; margin-bottom: 3px;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}}
.kp-stat-l {{
  font-size: .7rem; color: var(--kp-muted);
  text-transform: uppercase; letter-spacing: .07em; font-weight: 600;
}}

.kp-feat-grid {{
  display: grid; grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: 12px; margin-top: 8px;
}}
@media (max-width: 640px) {{
  .kp-feat-grid {{ grid-template-columns: 1fr; }}
}}
.kp-feat {{
  background: var(--kp-surface);
  border: 1px solid var(--kp-border);
  border-radius: 14px; padding: 18px;
}}
.kp-feat-ico {{
  width: 34px; height: 34px; border-radius: 9px;
  background: var(--kp-accent-soft); color: #6366f1;
  display: flex; align-items: center; justify-content: center;
  font-weight: 700; font-size: .95rem; margin-bottom: 12px;
}}
.kp-feat-t {{ font-weight: 700; font-size: .95rem; margin-bottom: 5px; }}
.kp-feat-d {{ font-size: .86rem; color: var(--kp-muted); line-height: 1.55; }}

.kp-balance {{
  background:
    radial-gradient(circle at 100% 0%, rgba(99,102,241,0.26), transparent 55%),
    linear-gradient(180deg, #090f1d 0%, #0f172a 100%);
  color: #e2e8f0;
  border-radius: 18px; padding: 24px 26px;
  margin: 12px 0 14px;
  border: 1px solid rgba(148,163,184,0.16);
}}
.kp-balance-top {{
  display: flex; justify-content: space-between; align-items: flex-start;
  flex-wrap: wrap; gap: 12px;
}}
.kp-balance-label {{
  font-size: .7rem; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: #94a3b8; margin-bottom: 6px;
}}
.kp-balance-value {{
  font-family: 'JetBrains Mono', monospace;
  font-size: 2.05rem; font-weight: 700; color: #f8fafc;
  letter-spacing: -.02em; margin-bottom: 8px;
}}
.kp-balance-chip {{
  font-size: .78rem; font-weight: 500; color: #cbd5e1;
  background: rgba(148,163,184,0.12);
  border: 1px solid rgba(148,163,184,0.22);
  padding: 6px 12px; border-radius: 999px;
}}
.kp-balance-meta {{ font-size: .82rem; color: #94a3b8; }}

.kp-user-head {{ display: flex; align-items: center; gap: 12px; }}
.kp-avatar {{
  width: 42px; height: 42px; border-radius: 12px;
  background: linear-gradient(135deg, #4f46e5, #6366f1);
  color: #fff; font-weight: 700; font-size: .95rem;
  display: flex; align-items: center; justify-content: center;
  flex-shrink: 0;
}}

.kp-section-label {{
  font-size: .72rem; font-weight: 700; letter-spacing: .1em;
  text-transform: uppercase; color: var(--kp-muted);
  margin: 26px 0 12px;
}}
.kp-section-label:first-child {{ margin-top: 10px; }}

.kp-steps {{ display: flex; flex-direction: column; gap: 10px; }}
.kp-step {{
  display: flex; gap: 18px;
  background: var(--kp-surface);
  border: 1px solid var(--kp-border);
  border-radius: 14px; padding: 18px 20px;
}}
.kp-step-n {{
  font-family: 'JetBrains Mono', monospace;
  font-size: .85rem; font-weight: 700; color: #6366f1;
  flex-shrink: 0; width: 28px; padding-top: 2px;
}}
.kp-step-t {{ font-weight: 700; margin-bottom: 4px; font-size: .96rem; }}
.kp-step-d {{ color: var(--kp-muted); font-size: .9rem; line-height: 1.6; }}

.kp-callout {{
  border-radius: 14px; padding: 18px 20px; margin: 6px 0;
  border: 1px solid var(--kp-border);
  background: var(--kp-surface);
}}
.kp-callout-title {{ font-weight: 700; margin-bottom: 6px; font-size: .94rem; }}
.kp-callout ul {{
  margin: 0; padding-left: 18px; font-size: .9rem;
  line-height: 1.7; color: var(--kp-muted);
}}
.kp-callout li {{ margin-bottom: 5px; }}
.kp-callout li:last-child {{ margin-bottom: 0; }}

.kp-empty {{
  border: 1px dashed var(--kp-border); border-radius: 14px;
  padding: 28px 20px; text-align: center;
}}
.kp-empty-title {{ font-weight: 600; font-size: .96rem; margin-bottom: 4px; }}
.kp-empty-sub {{ font-size: .86rem; color: var(--kp-muted); }}

.kp-row-sep {{ height: 1px; background: var(--kp-border); margin: 4px 0 8px; }}
.kp-hist-row {{
  display: flex; justify-content: space-between; align-items: center;
  gap: 10px; padding: 10px 14px; margin-bottom: 8px;
  border: 1px solid var(--kp-border); border-radius: 12px;
  background: var(--kp-surface);
}}

.kp-badge {{
  display: inline-block; font-size: .72rem; font-weight: 700;
  padding: 3px 10px; border-radius: 999px; letter-spacing: .02em;
  white-space: nowrap;
}}
.kp-badge-ok {{ background: rgba(16, 185, 129, 0.14); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.25); }}
.kp-badge-warn {{ background: rgba(245, 158, 11, 0.14); color: #d97706; border: 1px solid rgba(245, 158, 11, 0.28); }}
.kp-badge-err {{ background: rgba(239, 68, 68, 0.14); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.25); }}
.kp-badge-info {{ background: rgba(99, 102, 241, 0.14); color: #6366f1; border: 1px solid rgba(99, 102, 241, 0.28); }}
.kp-badge-muted {{ background: rgba(148, 163, 184, 0.14); color: var(--kp-muted); border: 1px solid rgba(148, 163, 184, 0.25); }}

.kp-footer {{
  margin-top: 44px; padding-top: 20px;
  border-top: 1px solid var(--kp-border);
  display: flex; justify-content: space-between; align-items: center;
  flex-wrap: wrap; gap: 10px; font-size: .8rem; color: var(--kp-muted);
}}
</style>
""", unsafe_allow_html=True)


def navbar():
    c = st.columns([3.2, 1, 1.1], vertical_alignment="center")
    c[0].markdown(
        '<div class="kp-nav-anchor kp-brand">'
        '  <span class="kp-brand-mark">KP</span>'
        '  <span>KirimPelanggan<span class="kp-brand-sub">Partner Portal</span></span>'
        '</div>',
        unsafe_allow_html=True,
    )
    with c[1]:
        st.page_link(P_HOME, label="Beranda", use_container_width=True)
    with c[2]:
        if st.session_state.get("user"):
            st.page_link(P_USER, label="Dashboard", use_container_width=True)
        else:
            st.page_link(P_AUTH, label="Masuk", use_container_width=True)
    st.markdown('<div class="kp-nav-divider"></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- Halaman Publik
def home_page():
    navbar()

    st.markdown("""
    <div class="kp-hero">
      <div class="kp-hero-top">
        <div class="kp-hero-badge"><span class="kp-pulse"></span>Sistem Operasional Aktif · WIB</div>
        <div class="kp-hero-badge">SLA Verifikasi 15 Mnt – 12 Jam</div>
      </div>
      <h1>Platform Kemitraan Tugas<br>Pelanggan Terkelola.</h1>
      <p>Ambil alokasi kontak eksklusif dari pusat, kerjakan sesuai standar panduan,
         unggah bukti penyelesaian, dan tarik komisi langsung ke rekening bank atau e-wallet Anda.</p>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.get("user"):
        if st.button("Buka Dashboard Mitra", type="primary", use_container_width=True):
            st.switch_page(P_USER)
    else:
        c1, c2 = st.columns([2, 1.2])
        if c1.button("Daftar & Mulai Sekarang", type="primary", use_container_width=True):
            st.switch_page(P_AUTH)
        if c2.button("Masuk Akun", use_container_width=True):
            st.switch_page(P_AUTH)

    st.markdown(f"""
    <div class="kp-kpi-grid kp-kpi-4">
      <div class="kp-stat">
        <div class="kp-stat-v">{rp_short(RATE)}</div>
        <div class="kp-stat-l">Komisi / Entri</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{DAILY:,}</div>
        <div class="kp-stat-l">Batas Klaim / Hari</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">{rp_short(MIN_WD)}</div>
        <div class="kp-stat-l">Min. Penarikan</div>
      </div>
      <div class="kp-stat">
        <div class="kp-stat-v">15m–12j</div>
        <div class="kp-stat-l">SLA Verifikasi</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Keunggulan Infrastruktur</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="kp-feat-grid">
      <div class="kp-feat">
        <div class="kp-feat-ico">01</div>
        <div class="kp-feat-t">Alokasi Eksklusif</div>
        <div class="kp-feat-d">Setiap kontak pelanggan hanya dialokasikan ke satu mitra pada periode aktif untuk mencegah duplikasi tugas.</div>
      </div>
      <div class="kp-feat">
        <div class="kp-feat-ico">02</div>
        <div class="kp-feat-t">Audit & Saldo Real-Time</div>
        <div class="kp-feat-d">Pantau status verifikasi bukti, riwayat kredit komisi, dan saldo siap tarik secara transparan di dashboard.</div>
      </div>
      <div class="kp-feat">
        <div class="kp-feat-ico">03</div>
        <div class="kp-feat-t">Pencairan Multi-Kanal</div>
        <div class="kp-feat-d">Mendukung transfer bank nasional (BCA, BRI, BNI, Mandiri) serta e-wallet populer (DANA, OVO, GoPay, ShopeePay).</div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Alur Kerja Mitra</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="kp-steps">
      <div class="kp-step">
        <div class="kp-step-n">01</div>
        <div>
          <div class="kp-step-t">Registrasi & Verifikasi Rekening</div>
          <div class="kp-step-d">Buat akun mitra dalam 30 detik dan cantumkan rekening bank atau e-wallet tujuan pencairan.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">02</div>
        <div>
          <div class="kp-step-t">Ambil Alokasi Tugas Harian</div>
          <div class="kp-step-d">Tentukan jumlah kontak yang ingin dikerjakan, maksimal <b>{DAILY:,}</b> entri per hari.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">03</div>
        <div>
          <div class="kp-step-t">Eksekusi Sesuai Panduan Operasional</div>
          <div class="kp-step-d">Gunakan template pesan resmi dari admin dan tandai setiap entri yang tuntas sebagai <b>Selesai</b>.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">04</div>
        <div>
          <div class="kp-step-t">Unggah Bukti & Kredit Komisi</div>
          <div class="kp-step-d">Kirim tangkapan layar bukti pengerjaan. Setelah disetujui, saldo bertambah <b>{rp_short(RATE)}</b> per entri selesai.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">05</div>
        <div>
          <div class="kp-step-t">Pencairan Dana</div>
          <div class="kp-step-d">Ajukan penarikan mulai <b>{rp_short(MIN_WD)}</b> kapan saja tanpa potongan tersembunyi.</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Kepatuhan & Kebijakan Data</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="kp-callout">
      <div class="kp-callout-title">Standar Operasional Wajib Mitra</div>
      <ul>
        <li>Stok harian direset otomatis pada pukul <b>00.00 WIB</b>. Pastikan tugas selesai ditandai dan bukti dikirim sebelum pergantian hari.</li>
        <li>Seluruh data kontak pelanggan bersifat rahasia. Dilarang menyalin, menyimpan di luar sistem, atau mendistribusikan ke pihak ketiga.</li>
        <li>Hentikan komunikasi segera apabila pelanggan menyatakan keberatan atau meminta berhenti.</li>
        <li>Pelanggaran terhadap ketentuan di atas berakibat penangguhan permanen dan pembatalan saldo.</li>
      </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Pertanyaan Umum (FAQ)</div>', unsafe_allow_html=True)
    with st.expander("Berapa lama proses verifikasi bukti pengerjaan?"):
        st.write("Tim operasional meninjau bukti secara berkala dalam 15 menit hingga maksimal 12 jam sejak unggahan diterima.")
    with st.expander("Apakah pengajuan bukti larut malam tetap aman jika melewati jam 00.00 WIB?"):
        st.write("Ya. Sistem menyimpan riwayat klaim dan bukti Anda selama beberapa hari sehingga verifikasi lintas hari tetap mengkreditkan saldo secara akurat.")
    with st.expander("Apa yang terjadi jika pengajuan penarikan ditolak?"):
        st.write("Apabila terjadi kendala rekening atau penolakan administratif, nominal penarikan akan dikembalikan penuh ke saldo akun Anda.")

    lic = get("settings.json", {}).get("license", "").strip()
    if lic:
        st.markdown('<div class="kp-section-label">Lisensi & Ketentuan Layanan</div>', unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(lic)

    st.markdown(f"""
    <div class="kp-footer">
      <span>© {now_wib().year} KirimPelanggan · Partner Operations Platform</span>
      <span>Zona Waktu Operasional: WIB (UTC+7)</span>
    </div>
    """, unsafe_allow_html=True)


def auth_page():
    if st.session_state.get("user"):
        st.switch_page(P_USER)
    navbar()

    st.markdown("""
    <div style="margin: 6px 0 22px;">
      <div class="kp-eyebrow" style="margin-bottom:8px;">Portal Akses Mitra</div>
      <h1 style="font-size:1.9rem;font-weight:800;letter-spacing:-.025em;margin:0 0 6px;">
        Masuk atau Daftar Akun</h1>
      <p class="kp-muted" style="font-size:.94rem;margin:0;line-height:1.6;">
        Pendaftaran gratis dan langsung aktif tanpa biaya administrasi.</p>
    </div>
    """, unsafe_allow_html=True)

    tab_l, tab_r = st.tabs(["Masuk", "Daftar Mitra Baru"])

    with tab_l:
        with st.form("f_login"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            ok = st.form_submit_button("Masuk ke Dashboard", type="primary", use_container_width=True)
        if ok:
            err = login(u, p)
            if err:
                st.error(err)
            else:
                st.switch_page(P_USER)

    with tab_r:
        with st.form("f_reg"):
            u = st.text_input("Username (4–24 karakter huruf/angka)")
            p = st.text_input("Password (minimal 6 karakter)", type="password")
            p2 = st.text_input("Konfirmasi Password", type="password")
            ok = st.form_submit_button("Buat Akun Mitra", type="primary", use_container_width=True)
        if ok:
            if p != p2:
                st.error("Konfirmasi password tidak cocok.")
            else:
                err = register(u, p)
                if err:
                    st.error(err)
                else:
                    login(u, p)
                    st.switch_page(P_USER)


# ---------------------------------------------------------------- Router
P_HOME = st.Page(home_page, title="Beranda", url_path="home", default=True)
P_AUTH = st.Page(auth_page, title="Masuk", url_path="masuk")
P_USER = st.Page(user_page, title="Dashboard", url_path="dashboard")
P_ADMIN = st.Page(admin_page, title="Admin", url_path="admin")

inject_css()
sync_session()
st.navigation([P_HOME, P_AUTH, P_USER, P_ADMIN], position="hidden").run()
