"""
KirimPelanggan — Enterprise Partner Operations Platform.
Secrets: S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET, ADMIN_PASSWORD
Opsional: S3_REGION (us-east-1), SESSION_SECRET
"""
import base64, csv, hashlib, hmac, html as html_lib, io, json, math, re, secrets, time, uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st
import streamlit.components.v1 as components
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

st.set_page_config(page_title="KirimPelanggan — Platform Kemitraan", page_icon="📨", layout="centered", initial_sidebar_state="collapsed")

RATE, MIN_WD, DAILY = 700, 10000, 1000
PAGE_SIZE, MAX_PROOF_MB, MAX_PROOF_FILES = 20, 5, 10
CLAIM_RETENTION_DAYS, SESSION_TTL = 3, 7 * 86400
WIB = timezone(timedelta(hours=7))
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

now_wib = lambda: datetime.now(WIB)
today = lambda: now_wib().strftime("%Y-%m-%d")
esc = lambda v: html_lib.escape("" if v is None else str(v), quote=True)
rp = lambda n: "Rp" + f"{float(n):,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
rp_short = lambda n: "Rp" + f"{int(n):,}".replace(",", ".")

BADGES = {
    "pending": ("Menunggu", "warn"), "disetujui": ("Disetujui", "ok"),
    "dibayar": ("Dibayar", "ok"), "ditolak": ("Ditolak", "err"),
    "terkredit": ("Terkredit", "ok"), "selesai": ("Selesai", "info"),
    "belum": ("Belum", "muted"), "aktif": ("Aktif", "ok"), "diblokir": ("Diblokir", "err"),
}
badge_html = lambda s: (lambda l, c: f'<span class="kp-badge kp-b-{c}">{esc(l)}</span>')(*BADGES.get((s or "").lower(), (str(s).capitalize(), "muted")))
kpi_grid = lambda items: '<div class="kp-kpi">' + "".join(f'<div class="kp-card kp-stat"><div class="kp-sv">{v}</div><div class="kp-sl">{l}</div></div>' for v, l in items) + "</div>"


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
        return json.loads(client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read())
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return default
        raise


def put(key: str, obj):
    client().put_object(Bucket=BUCKET, Key=PREFIX + key, Body=json.dumps(obj, ensure_ascii=False).encode("utf-8"), ContentType="application/json")


delete_key = lambda k: client().delete_object(Bucket=BUCKET, Key=PREFIX + k)


def get_bytes(key: str):
    try:
        return client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read()
    except ClientError:
        return None


def list_keys(prefix: str) -> list[str]:
    keys, token, full = [], None, PREFIX + prefix
    while True:
        r = client().list_objects_v2(Bucket=BUCKET, Prefix=full, **({"ContinuationToken": token} if token else {}))
        keys.extend(o["Key"][len(PREFIX):] for o in r.get("Contents", []))
        if not r.get("IsTruncated"):
            break
        token = r["NextContinuationToken"]
    return keys


@st.cache_data(ttl=3600, show_spinner=False)
def cleanup(day: str) -> bool:
    cutoff = (datetime.strptime(day, "%Y-%m-%d") - timedelta(days=CLAIM_RETENTION_DAYS)).strftime("%Y-%m-%d")
    for k in list_keys("db/"):
        p = k.split("/")
        if len(p) >= 3 and DATE_RE.match(p[1]) and p[1] < day:
            delete_key(k)
    for pref in ("claims/", "proofs/"):
        for k in list_keys(pref):
            p = k.split("/")
            if len(p) >= 3 and DATE_RE.match(p[1]) and p[1] < cutoff:
                delete_key(k)
    return True


@st.cache_data(ttl=86400, show_spinner=False)
def migrate_users_if_needed() -> bool:
    if get("migrations/users_v2.json", None):
        return True
    legacy = get("users.json", {})
    if legacy:
        existing = set(list_keys("users/"))
        for u, data in legacy.items():
            if f"users/{u}.json" not in existing:
                put(f"users/{u}.json", data)
    put("migrations/users_v2.json", {"done": True, "at": now_wib().isoformat()})
    return True


user_key = lambda u: f"users/{u.strip().lower()}.json"
get_user = lambda u: get(user_key(u), None) if u.strip() else None
save_user = lambda u, d: put(user_key(u), d)


def load_all_users() -> dict[str, dict]:
    keys = [k for k in list_keys("users/") if k.endswith(".json")]
    if not keys:
        return {}
    out = {}
    with ThreadPoolExecutor(max_workers=12) as ex:
        for uname, data in ex.map(lambda k: (k[6:-5], get(k, None)), keys):
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


# ---------------------------------------------------------------- Parser
def parse_db_lines(raw: str) -> list[dict]:
    out, seen = [], set()
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        p = s.split(None, 1)
        nomor, nama = p[0].strip(), (p[1].strip() if len(p) > 1 else "")
        if nomor and nomor not in seen:
            seen.add(nomor)
            out.append({"nomor": nomor, **({"nama": nama} if nama else {})})
    return out


def parse_csv_bytes(content: bytes) -> list[dict]:
    text = content.decode("utf-8", errors="replace")
    delim = next((c for c in (",", ";", "\t") if c in "\n".join(text.splitlines()[:5])), ",")
    out, seen, hdr = [], set(), {"nomor", "number", "phone", "hp", "no_hp", "no", "telp"}
    for idx, row in enumerate(csv.reader(io.StringIO(text), delimiter=delim)):
        if not row:
            continue
        first = row[0].strip()
        if not first or first.startswith("#") or (idx == 0 and first.lower() in hdr) or first in seen:
            continue
        seen.add(first)
        nama = row[1].strip() if len(row) > 1 else ""
        out.append({"nomor": first, **({"nama": nama} if nama else {})})
    return out


def parse_db_file(up) -> list[dict]:
    name, content = (up.name or "").lower(), up.getvalue()
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
    return parse_csv_bytes(content) if name.endswith(".csv") else parse_db_lines(content.decode("utf-8", errors="replace"))


entry_nomor = lambda d: (d.get("nomor") or d.get("number") or d.get("phone") or d.get("hp")) if isinstance(d, dict) else None
entry_nama = lambda d: (d.get("nama") or d.get("name")) if isinstance(d, dict) else None
fmt_account = lambda a: f"{a.get('type','-')} · {a.get('number','-')} · a.n. {a.get('name','-')}" if a else "Belum didaftarkan"


# ---------------------------------------------------------------- Auth & Sesi
def _session_secret() -> bytes:
    raw = st.secrets.get("SESSION_SECRET") or (st.secrets["ADMIN_PASSWORD"] + "|" + st.secrets["S3_SECRET_KEY"])
    return hashlib.sha256(raw.encode()).digest()


def make_session_token(u: str, pw_hash: str, ttl: int = SESSION_TTL) -> str:
    b64 = base64.urlsafe_b64encode(json.dumps({"u": u, "v": pw_hash[:8], "exp": int(time.time()) + ttl}, separators=(",", ":")).encode()).decode().rstrip("=")
    return f"{b64}.{hmac.new(_session_secret(), b64.encode(), hashlib.sha256).hexdigest()[:24]}"


def verify_session_token(tok: str) -> tuple[str, str] | None:
    try:
        b64, sig = tok.split(".", 1)
        if not hmac.compare_digest(sig, hmac.new(_session_secret(), b64.encode(), hashlib.sha256).hexdigest()[:24]):
            return None
        d = json.loads(base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4)))
        return (str(d["u"]), str(d["v"])) if int(d["exp"]) >= int(time.time()) else None
    except Exception:
        return None


def sync_session():
    if st.session_state.get("user") and st.session_state.get("sid"):
        if st.query_params.get("s") != st.session_state.sid:
            st.query_params["s"] = st.session_state.sid
        return
    tok = st.query_params.get("s")
    if not tok:
        return
    parsed = verify_session_token(tok)
    if parsed:
        rec = get_user(parsed[0])
        if rec and not rec.get("banned") and rec["pw"][:8] == parsed[1]:
            st.session_state.user, st.session_state.sid = parsed[0], tok
            return
    st.query_params.pop("s", None)


def clear_session():
    for k in ("user", "sid", "acc_prompted"):
        st.session_state.pop(k, None)
    st.query_params.pop("s", None)


def bridge_session_to_parent(sid: str):
    components.html(f"<script>try{{window.top.postMessage({json.dumps({'type':'kp_sid','sid':sid or ''})},'*');}}catch(e){{}}</script>", height=0)


hash_pw = lambda pw, salt: hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()


def register(username: str, pw: str) -> str | None:
    u = username.strip().lower()
    if not u.isalnum() or not (4 <= len(u) <= 24):
        return "Username harus 4–24 karakter (huruf dan angka saja)."
    if len(pw) < 6:
        return "Password minimal 6 karakter."
    if get_user(u) is not None:
        return "Username sudah dipakai."
    salt = secrets.token_hex(16)
    save_user(u, {"salt": salt, "pw": hash_pw(pw, salt), "balance": 0, "account": None, "banned": False, "created": now_wib().isoformat()})
    return None


def login(username: str, pw: str) -> str | None:
    u = username.strip().lower()
    rec = get_user(u)
    if not rec or not secrets.compare_digest(hash_pw(pw, rec["salt"]), rec["pw"]):
        return "Username atau password salah."
    if rec.get("banned"):
        return "Akun diblokir. Hubungi tim operasional."
    tok = make_session_token(u, rec["pw"])
    st.session_state.user, st.session_state.sid = u, tok
    st.query_params["s"] = tok
    return None


# ---------------------------------------------------------------- Klaim
claim_key = lambda user, day=None: f"claims/{day or today()}/{user}.json"


def request_db(user: str, n: int) -> tuple[int, str | None]:
    d = today()
    mine = get(claim_key(user, d), [])
    allow = min(n, DAILY - len(mine))
    if allow <= 0:
        return 0, "Batas klaim harian tercapai."
    pool, assigned = get(f"db/{d}/pool.json", []), get(f"db/{d}/assigned.json", {})
    free = [x for x in pool if x["id"] not in assigned][:allow]
    if not free:
        return 0, "Stok entri hari ini sedang habis. Silakan cek kembali nanti."
    for x in free:
        assigned[x["id"]] = user
        mine.append({"id": x["id"], "data": x["data"], "status": False, "credited": False})
    put(f"db/{d}/assigned.json", assigned)
    put(claim_key(user, d), mine)
    return len(free), None


# ---------------------------------------------------------------- Komponen
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
    h = max(145, min(120 + (text.count("\n") + 1) * 22, 520))
    bg, hb, fg, bd, mt = ("#0f172a", "#111c33", "#e2e8f0", "#1e293b", "#94a3b8") if is_dark() else ("#fff", "#f8fafc", "#0f172a", "#e2e8f0", "#475569")
    components.html(f"""<!DOCTYPE html><html><head><meta charset="utf-8"><style>*{{box-sizing:border-box}}body{{margin:0;background:transparent;font-family:Inter,system-ui,sans-serif}}.w{{background:{bg};border:1px solid {bd};border-radius:14px;overflow:hidden;color:{fg}}}.h{{display:flex;justify-content:space-between;align-items:center;padding:10px 16px;background:{hb};border-bottom:1px solid {bd};font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:{mt}}}.b{{background:{bg};color:{fg};border:1px solid {bd};border-radius:8px;padding:5px 12px;cursor:pointer;font-size:12px;font-weight:600}}.b:hover{{border-color:#4f46e5;color:#4f46e5}}pre{{margin:0;padding:16px 18px;white-space:pre-wrap;word-break:break-word;font-family:'JetBrains Mono',monospace;font-size:13px;line-height:1.65}}</style></head><body><div class="w"><div class="h"><span>{esc(label)}</span><button class="b" id="cp" type="button">Salin Teks</button></div><pre>{esc(text)}</pre></div><script>const t={payload},b=document.getElementById('cp');b.onclick=async()=>{{try{{await navigator.clipboard.writeText(t)}}catch(e){{const a=document.createElement('textarea');a.value=t;document.body.appendChild(a);a.select();document.execCommand('copy');document.body.removeChild(a)}}b.textContent='✓ Tersalin';setTimeout(()=>b.textContent='Salin Teks',1600)}};</script></body></html>""", height=h)


@st.dialog("Rekening Tujuan Penarikan")
def account_dialog():
    st.caption("Pastikan nomor rekening atau e-wallet sesuai dengan nama pemilik.")
    user = st.session_state.get("user")
    cur = (get_user(user) or {}).get("account") or {}
    opts = ["DANA", "OVO", "GoPay", "ShopeePay", "BCA", "BRI", "BNI", "Mandiri", "Lainnya"]
    kind = st.selectbox("Bank / E-Wallet", opts, index=opts.index(cur["type"]) if cur.get("type") in opts else 0)
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
        fresh["account"] = {"type": kind, "number": num.strip(), "name": name.strip()}
        save_user(user, fresh)
        st.session_state.acc_prompted = True
        st.rerun()


@st.fragment
def task_list_fragment(user: str, d: str, mine: list[dict]):
    if not mine:
        st.markdown('<div class="kp-empty"><b>Belum ada tugas diambil hari ini</b><div class="kp-muted" style="font-size:.86rem;margin-top:4px;">Gunakan formulir di atas untuk mengambil entri pelanggan.</div></div>', unsafe_allow_html=True)
        return
    f1, f2 = st.columns([1.4, 2])
    filt = f1.selectbox("Filter", ["Semua", "Belum selesai", "Selesai (belum kredit)", "Sudah dikredit"], label_visibility="collapsed")
    q = f2.text_input("Cari", placeholder="Cari nomor atau nama...", label_visibility="collapsed").strip().lower()

    indexed = [(i, x) for i, x in enumerate(mine)
               if (filt == "Semua" or (filt == "Belum selesai" and not x["status"])
                   or (filt == "Selesai (belum kredit)" and x["status"] and not x["credited"])
                   or (filt == "Sudah dikredit" and x["credited"]))
               and (not q or q in str(entry_nomor(x["data"]) or "").lower() or q in str(entry_nama(x["data"]) or "").lower())]

    total_pages = max(1, math.ceil(len(indexed) / PAGE_SIZE))
    pk = "task_page_num"
    if pk in st.session_state and st.session_state[pk] > total_pages:
        st.session_state[pk] = total_pages
    if pk not in st.session_state:
        st.session_state[pk] = 1

    p1, p2, p3 = st.columns([1.4, 1.4, 1.8], vertical_alignment="center")
    p1.caption(f"Menampilkan {len(indexed)} dari {len(mine)} entri")
    cur_page = int(p2.number_input("Hal", min_value=1, max_value=total_pages, step=1, label_visibility="collapsed", key=pk)) if total_pages > 1 else 1
    if total_pages == 1:
        p2.caption("Halaman 1 / 1")

    page_items = indexed[(cur_page - 1) * PAGE_SIZE:cur_page * PAGE_SIZE]
    if p3.button("Tandai Halaman Ini Selesai", use_container_width=True, disabled=not page_items):
        fresh = get(claim_key(user, d), [])
        changed = False
        for idx, _ in page_items:
            if idx < len(fresh) and not fresh[idx]["credited"] and not fresh[idx]["status"]:
                fresh[idx]["status"] = True
                changed = True
        if changed:
            put(claim_key(user, d), fresh)
            st.rerun()

    if not page_items:
        st.caption("Tidak ada entri yang cocok dengan filter.")
        return

    with st.form("tasks_batch_form"):
        new_vals = {}
        for pos, (idx, item) in enumerate(page_items):
            nomor, nama = entry_nomor(item["data"]), entry_nama(item["data"])
            rl, rm, rr = st.columns([2.6, 1.2, 1], vertical_alignment="center")
            if nomor:
                rl.code(str(nomor), language=None)
                if nama:
                    rl.caption(str(nama))
            else:
                rl.code(json.dumps(item["data"], ensure_ascii=False), language=None)
            rm.markdown(badge_html("terkredit" if item["credited"] else ("selesai" if item["status"] else "belum")), unsafe_allow_html=True)
            new_vals[idx] = rr.checkbox("Selesai", value=item["status"], key=f"chk_{d}_{item['id']}", disabled=item["credited"])
            if pos < len(page_items) - 1:
                st.markdown('<div class="kp-sep"></div>', unsafe_allow_html=True)
        save_tasks = st.form_submit_button("Simpan Perubahan Status", type="primary", use_container_width=True)

    if save_tasks:
        fresh = get(claim_key(user, d), [])
        changed = False
        for idx, val in new_vals.items():
            if idx < len(fresh) and not fresh[idx]["credited"] and fresh[idx]["status"] != val:
                fresh[idx]["status"] = val
                changed = True
        if changed:
            put(claim_key(user, d), fresh)
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
    pill = badge_html("aktif") if me.get("account") else '<span class="kp-badge kp-b-warn">Rekening Belum Diisi</span>'
    top[0].markdown(f'<div class="kp-nav-anchor kp-uhead"><div class="kp-avatar">{esc(user[:2].upper())}</div><div><div class="kp-eye">Mitra Terdaftar</div><div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;"><b style="font-size:1.15rem;">@{esc(user)}</b>{pill}</div></div></div>', unsafe_allow_html=True)
    if top[1].button("Keluar", use_container_width=True):
        clear_session()
        st.switch_page(P_HOME)

    if not me.get("account"):
        st.warning("Lengkapi rekening bank atau e-wallet terlebih dahulu agar dapat melakukan penarikan.")
        if st.button("Daftarkan Rekening Sekarang", type="primary"):
            account_dialog()

    acc = me.get("account")
    acc_line = f"{esc(acc['type'])} · {esc(acc['number'])} ({esc(acc['name'])})" if acc else "Belum ada rekening tujuan"
    st.markdown(f'<div class="kp-dark kp-bal"><div class="kp-bal-top"><div><div class="kp-eye" style="color:#94a3b8;">Saldo Tersedia</div><div class="kp-bal-val">{rp(me["balance"])}</div></div><div class="kp-chip">{acc_line}</div></div><div style="font-size:.82rem;color:#94a3b8;">Minimal penarikan {rp_short(MIN_WD)} · Komisi {rp_short(RATE)} / entri terverifikasi</div></div>', unsafe_allow_html=True)

    d = today()
    mine = get(claim_key(user, d), [])
    done = sum(1 for x in mine if x["status"])
    pending_verif = sum(1 for x in mine if x["status"] and not x["credited"])
    est_pending = pending_verif * RATE
    st.markdown(kpi_grid([(f"{len(mine)}/{DAILY}", "Klaim Hari Ini"), (done, "Tandai Selesai"), (pending_verif, "Menunggu Verif"), (rp_short(est_pending), "Potensi Masuk")]), unsafe_allow_html=True)

    st.write("")
    tab_kerja, tab_wd = st.tabs(["Ruang Kerja", "Penarikan & Rekening"])

    with tab_kerja:
        st.markdown('<div class="kp-sec">1 · Instruksi Operasional</div>', unsafe_allow_html=True)
        copy_block(get("settings.json", {"text": ""}).get("text", ""), "Teks Panduan dari Admin")

        st.markdown('<div class="kp-sec">2 · Ambil Antrean Tugas</div>', unsafe_allow_html=True)
        rem = DAILY - len(mine)
        if rem <= 0:
            st.info(f"Kuota harian penuh ({DAILY}/{DAILY} entri). Reset otomatis pada 00.00 WIB.")
        else:
            with st.form("claim_form"):
                c1, c2 = st.columns([3, 1.3], vertical_alignment="bottom")
                n = c1.number_input(f"Jumlah entri baru (sisa kuota: {rem})", min_value=1, max_value=rem, value=min(10, rem), step=1)
                submit = c2.form_submit_button("Ambil Tugas", type="primary", use_container_width=True)
            if submit:
                with st.spinner("Mengalokasikan entri eksklusif..."):
                    got, err = request_db(user, int(n))
                if err:
                    st.warning(err)
                else:
                    st.success(f"{got} entri baru ditambahkan.")
                    st.rerun()

        st.markdown('<div class="kp-sec">3 · Daftar Tugas Pelanggan</div>', unsafe_allow_html=True)
        task_list_fragment(user, d, mine)

        st.markdown('<div class="kp-sec">4 · Unggah Bukti Pengerjaan</div>', unsafe_allow_html=True)
        st.caption("Tandai minimal 1 entri berstatus **Selesai** di atas sebelum mengirim bukti." if pending_verif == 0 else f"Anda memiliki **{pending_verif} entri selesai** ({rp_short(est_pending)}) siap diverifikasi.")
        files = st.file_uploader(f"Screenshot bukti (PNG/JPG/WEBP, maks {MAX_PROOF_MB} MB)", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True, label_visibility="collapsed")
        if st.button("Kirim Bukti untuk Verifikasi", type="primary", disabled=(not files or pending_verif == 0), use_container_width=True):
            if len(files) > MAX_PROOF_FILES:
                st.error(f"Maksimal {MAX_PROOF_FILES} file per pengiriman.")
            elif bad := [f.name for f in files if len(f.getvalue()) > MAX_PROOF_MB * 1024 * 1024]:
                st.error(f"Ukuran file > {MAX_PROOF_MB} MB: {', '.join(bad)}")
            else:
                proofs = get("proofs.json", [])
                for f in files:
                    ext = f.name.rsplit(".", 1)[-1].lower()
                    key = f"proofs/{d}/{user}-{uuid.uuid4().hex[:8]}.{ext}"
                    client().put_object(Bucket=BUCKET, Key=PREFIX + key, Body=f.getvalue())
                    proofs.append({"id": uuid.uuid4().hex, "user": user, "date": d, "key": key, "claimed_count": pending_verif, "status": "pending", "time": now_wib().isoformat()})
                put("proofs.json", proofs)
                st.success("Bukti terkirim. Verifikasi diproses dalam 15 menit – 12 jam.")
                st.rerun()

        if my_proofs := [p for p in get("proofs.json", []) if p["user"] == user][-5:]:
            st.markdown('<div class="kp-sec">Riwayat Pengiriman Bukti</div>', unsafe_allow_html=True)
            for p in reversed(my_proofs):
                st.markdown(f'<div class="kp-card kp-hrow"><div><span class="kp-mono">{esc(p["time"][:16].replace("T"," "))}</span> · Klaim {esc(p.get("claimed_count","-"))} entri</div><div>{badge_html(p["status"])}</div></div>', unsafe_allow_html=True)

    with tab_wd:
        st.markdown('<div class="kp-sec">Rekening Tujuan Pencairan</div>', unsafe_allow_html=True)
        if acc:
            st.markdown(f'<div class="kp-card"><b>{esc(acc["type"])} · <span class="kp-mono">{esc(acc["number"])}</span></b><div class="kp-muted" style="margin-top:4px;">Atas nama: <b>{esc(acc["name"])}</b></div></div>', unsafe_allow_html=True)
        else:
            st.caption("Rekening penarikan belum didaftarkan.")
        if st.button("Ubah Rekening Tujuan"):
            account_dialog()

        st.markdown('<div class="kp-sec">Ajukan Penarikan Dana</div>', unsafe_allow_html=True)
        cur_bal = int(me["balance"])
        if cur_bal < MIN_WD:
            st.info(f"Saldo Anda {rp(cur_bal)}. Minimal penarikan adalah {rp_short(MIN_WD)}.")
        elif not acc:
            st.warning("Daftarkan rekening terlebih dahulu sebelum mengajukan penarikan.")
        else:
            with st.form("wd_form"):
                amt = st.number_input(f"Nominal penarikan (tersedia: {rp_short(cur_bal)})", min_value=MIN_WD, max_value=cur_bal, step=1000, value=cur_bal)
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
                    wd.append({"id": uuid.uuid4().hex, "user": user, "amount": int(amt), "account": fresh["account"], "status": "pending", "time": now_wib().isoformat()})
                    put("wd.json", wd)
                    st.success("Pengajuan penarikan berhasil dikirim.")
                    st.rerun()

        if my_wd := [w for w in get("wd.json", []) if w["user"] == user][-10:]:
            st.markdown('<div class="kp-sec">Riwayat Penarikan</div>', unsafe_allow_html=True)
            for w in reversed(my_wd):
                wa = w.get("account") or {}
                st.markdown(f'<div class="kp-card kp-hrow"><div><b>{rp(w["amount"])}</b><div class="kp-muted" style="font-size:.8rem;"><span class="kp-mono">{esc(w["time"][:16].replace("T"," "))}</span> · {esc(wa.get("type",""))} {esc(wa.get("number",""))}</div></div><div>{badge_html(w["status"])}</div></div>', unsafe_allow_html=True)

    bridge_session_to_parent(st.session_state.get("sid", ""))


# ---------------------------------------------------------------- Admin Console
def admin_page():
    if not st.session_state.get("admin"):
        st.markdown('<div style="margin:12px 0 24px;"><div class="kp-eye">Internal Operations</div><h1 style="font-size:1.85rem;margin:4px 0 6px;">Admin Console</h1><p class="kp-muted" style="margin:0;">Akses terbatas untuk tim operasional.</p></div>', unsafe_allow_html=True)
        tries = st.session_state.get("admin_tries", 0)
        with st.form("admin_login"):
            p = st.text_input("Password Administrator", type="password")
            ok = st.form_submit_button("Masuk Console", type="primary", use_container_width=True)
        if ok:
            if tries >= 5:
                st.error("Terlalu banyak percobaan gagal. Muat ulang halaman.")
            elif secrets.compare_digest(p.encode(), st.secrets["ADMIN_PASSWORD"].encode()):
                st.session_state.admin, st.session_state.admin_tries = True, 0
                st.rerun()
            else:
                st.session_state.admin_tries = tries + 1
                st.error("Password administrator tidak sesuai.")
        return

    top = st.columns([4, 1.2], vertical_alignment="center")
    top[0].markdown('<div class="kp-nav-anchor"><div class="kp-eye">Internal Operations</div><div style="font-size:1.3rem;font-weight:700;">Admin Console</div></div>', unsafe_allow_html=True)
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("admin", None)
        st.rerun()

    d = today()
    users, wd, proofs = load_all_users(), get("wd.json", []), get("proofs.json", [])
    pool, assigned = get(f"db/{d}/pool.json", []), get(f"db/{d}/assigned.json", {})
    pending_wd = [w for w in wd if w["status"] == "pending"]
    pending_proofs = [p for p in proofs if p["status"] == "pending"]

    st.markdown(kpi_grid([
        (len(users), "Total Mitra"),
        (len(pending_wd), f"WD Pending ({rp_short(sum(int(w['amount']) for w in pending_wd))})"),
        (len(pending_proofs), "Bukti Menunggu"),
        (f"{len(pool) - len(assigned)}/{len(pool)}", "Sisa Stok DB"),
    ]), unsafe_allow_html=True)
    st.write("")

    t_db, t_user, t_wd, t_up, t_set, t_home = st.tabs(["Stok DB", "Mitra", "Penarikan", "Verifikasi Bukti", "Instruksi", "Beranda & Lisensi"])

    with t_db:
        if "db_flash" in st.session_state:
            st.success(st.session_state.pop("db_flash"))
        st.caption(f"Periode **{d} (WIB)** · Total {len(pool)} · Terpakai {len(assigned)} · Tersedia {len(pool) - len(assigned)}")
        src = st.radio("Metode input", ["Input Teks", "Unggah File (.txt / .csv / .json)"], horizontal=True)
        raw = st.text_area("Daftar entri", height=200, placeholder="081234567890 Budi\n081234567891\n081234567892 Siti", label_visibility="collapsed") if src == "Input Teks" else ""
        up = None if src == "Input Teks" else st.file_uploader("Pilih file .txt, .csv, atau .json", type=["txt", "csv", "json"], key="db_up")
        if st.button("Tambahkan ke Stok Hari Ini", type="primary"):
            entries = None
            if src == "Input Teks":
                entries = parse_db_lines(raw) if raw.strip() else st.warning("Tempel data entri terlebih dahulu.")
            elif up is not None:
                try:
                    entries = parse_db_file(up)
                except Exception as e:
                    st.error(f"File tidak valid: {e}")
            else:
                st.warning("Unggah file terlebih dahulu.")
            if isinstance(entries, list):
                if not entries:
                    st.warning("Tidak ada entri valid.")
                else:
                    fp = get(f"db/{d}/pool.json", [])
                    ex_n, ex_j = {entry_nomor(x["data"]) for x in fp if entry_nomor(x["data"])}, {json.dumps(x["data"], sort_keys=True) for x in fp}
                    added = skipped = 0
                    for e in entries:
                        n, k = entry_nomor(e), json.dumps(e, sort_keys=True)
                        if (n and n in ex_n) or k in ex_j:
                            skipped += 1
                            continue
                        if n:
                            ex_n.add(n)
                        ex_j.add(k)
                        fp.append({"id": uuid.uuid4().hex[:12], "data": e})
                        added += 1
                    put(f"db/{d}/pool.json", fp)
                    st.session_state.db_flash = f"{added} entri ditambahkan ke stok {d}" + (f" ({skipped} duplikat dilewati)" if skipped else "")
                    st.rerun()
        if assigned:
            by_u = {}
            for _, uname in assigned.items():
                by_u[uname] = by_u.get(uname, 0) + 1
            st.caption("Distribusi hari ini: " + ", ".join(f"@{u} ({c})" for u, c in sorted(by_u.items())))

    with t_user:
        if not users:
            st.caption("Belum ada mitra terdaftar.")
        else:
            q_u = st.text_input("Cari username", placeholder="Ketik username mitra...").strip().lower()
            f_users = {u: v for u, v in users.items() if not q_u or q_u in u}
            st.dataframe([{"Username": f"@{u}", "Saldo": rp_short(v.get("balance", 0)), "Rekening": fmt_account(v.get("account")), "Status": "Diblokir" if v.get("banned") else "Aktif", "Terdaftar": v.get("created", "")[:10]} for u, v in f_users.items()], use_container_width=True, hide_index=True)
            if f_users:
                sel = st.selectbox("Kelola mitra", list(f_users.keys()), format_func=lambda x: f"@{x}")
                v, ct = users[sel], get(claim_key(sel, d), [])
                with st.container(border=True):
                    st.write(f"**@{sel}** · Terdaftar `{v.get('created','')[:16].replace('T',' ')}` · Hari ini: Klaim **{len(ct)}**, Selesai **{sum(1 for x in ct if x['status'])}**")
                    st.write(f"Rekening: {fmt_account(v.get('account'))}")
                    c1, c2, c3 = st.columns([1.4, 1, 1], vertical_alignment="bottom")
                    nb = c1.number_input("Saldo (Rp)", value=int(v.get("balance", 0)), step=1500, key=f"nb_{sel}")
                    if c1.button("Simpan Saldo", key=f"sv_{sel}", type="primary", use_container_width=True):
                        if fr := get_user(sel):
                            fr["balance"] = int(nb)
                            save_user(sel, fr)
                            st.rerun()
                    if c2.button("Buka Blokir" if v.get("banned") else "Blokir Akun", key=f"bn_{sel}", use_container_width=True):
                        if fr := get_user(sel):
                            fr["banned"] = not fr.get("banned", False)
                            save_user(sel, fr)
                            st.rerun()
                    if c3.button("Hapus Akun", key=f"dl_{sel}", use_container_width=True):
                        delete_key(user_key(sel))
                        st.rerun()

    with t_wd:
        if not pending_wd:
            st.info("Tidak ada permintaan penarikan yang menunggu.")
        for w in reversed(pending_wd):
            a = w.get("account") or {}
            with st.container(border=True):
                st.write(f"**@{w['user']}** · **{rp(w['amount'])}**")
                st.caption(f"{a.get('type','-')} · {a.get('number','-')} · a.n. {a.get('name','-')} · {w['time'][:16].replace('T',' ')}")
                c = st.columns(2)
                if c[0].button("Tandai Sudah Dibayar", key=f"p_{w['id']}", type="primary", use_container_width=True):
                    fw = get("wd.json", [])
                    for item in fw:
                        if item["id"] == w["id"] and item["status"] == "pending":
                            item["status"], item["processed_at"] = "dibayar", now_wib().isoformat()
                    put("wd.json", fw)
                    st.rerun()
                if c[1].button("Tolak & Kembalikan Saldo", key=f"r_{w['id']}", use_container_width=True):
                    fw, ref = get("wd.json", []), False
                    for item in fw:
                        if item["id"] == w["id"] and item["status"] == "pending":
                            item["status"], item["processed_at"], ref = "ditolak", now_wib().isoformat(), True
                    if ref:
                        if fu := get_user(w["user"]):
                            fu["balance"] = int(fu["balance"]) + int(w["amount"])
                            save_user(w["user"], fu)
                        put("wd.json", fw)
                    st.rerun()
        if done_wd := [w for w in wd if w["status"] != "pending"]:
            buf = io.StringIO()
            wr = csv.writer(buf)
            wr.writerow(["Waktu", "Username", "Nominal", "Bank/E-Wallet", "Nomor", "Atas Nama", "Status"])
            for w in reversed(done_wd):
                a = w.get("account") or {}
                wr.writerow([w["time"][:19], w["user"], w["amount"], a.get("type", ""), a.get("number", ""), a.get("name", ""), w["status"]])
            st.download_button("Unduh Riwayat Penarikan (.csv)", buf.getvalue().encode("utf-8"), f"riwayat-penarikan-{d}.csv", "text/csv")
            for w in reversed(done_wd[-10:]):
                st.markdown(f'<div class="kp-card kp-hrow"><div>@{esc(w["user"])} · <b>{rp(w["amount"])}</b> <span class="kp-muted kp-mono" style="font-size:.8rem;">{esc(w["time"][:16].replace("T"," "))}</span></div><div>{badge_html(w["status"])}</div></div>', unsafe_allow_html=True)

    with t_up:
        if not pending_proofs:
            st.info("Tidak ada bukti pengerjaan yang menunggu verifikasi.")
        for p in reversed(pending_proofs):
            with st.container(border=True):
                st.write(f"**@{p['user']}** · `{p['date']}` · Klaim **{p.get('claimed_count','-')} entri** selesai")
                if img := get_bytes(p["key"]):
                    st.image(img, width=360)
                c = st.columns(2)
                if c[0].button("Setujui & Kreditkan Saldo", key=f"a_{p['id']}", type="primary", use_container_width=True):
                    claims = get(claim_key(p["user"], p["date"]), [])
                    n = 0
                    for x in claims:
                        if x["status"] and not x["credited"]:
                            x["credited"] = True
                            n += 1
                    if n:
                        if fu := get_user(p["user"]):
                            fu["balance"] = int(fu["balance"]) + n * RATE
                            save_user(p["user"], fu)
                        put(claim_key(p["user"], p["date"]), claims)
                    fp = get("proofs.json", [])
                    for item in fp:
                        if item["id"] == p["id"]:
                            item["status"], item["credited_entries"] = "disetujui", n
                    put("proofs.json", fp)
                    st.rerun()
                if c[1].button("Tolak Bukti", key=f"x_{p['id']}", use_container_width=True):
                    fp = get("proofs.json", [])
                    for item in fp:
                        if item["id"] == p["id"]:
                            item["status"] = "ditolak"
                    put("proofs.json", fp)
                    st.rerun()
        st.caption(f"Disetujui: {sum(1 for p in proofs if p['status']=='disetujui')} · Ditolak: {sum(1 for p in proofs if p['status']=='ditolak')}")

    with t_set:
        cfg = get("settings.json", {"text": ""})
        txt = st.text_area("Teks instruksi & template pesan untuk mitra", value=cfg.get("text", ""), height=220)
        if st.button("Simpan Instruksi", type="primary"):
            cfg["text"] = txt
            put("settings.json", cfg)
            st.success("Instruksi diperbarui.")

    with t_home:
        cfg = get("settings.json", {"text": ""})
        lic = st.text_area("Lisensi & Ketentuan (Markdown, tampil di Beranda)", value=cfg.get("license", ""), height=280)
        if st.button("Simpan Konten Beranda", type="primary"):
            cfg["license"] = lic
            put("settings.json", cfg)
            st.success("Konten beranda disimpan.")


# ---------------------------------------------------------------- Design System CSS
def inject_css():
    mt = "#94a3b8" if is_dark() else "#475569"
    st.markdown(f"""<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap');
:root{{--kp-acs:rgba(79,70,229,.12);--kp-bd:rgba(148,163,184,.24);--kp-sf:var(--secondary-background-color,rgba(148,163,184,.08));--kp-mt:{mt};}}
header[data-testid="stHeader"],[data-testid="stToolbar"],[data-testid="stDecoration"],[data-testid="stStatusWidget"],#MainMenu,footer{{display:none!important;visibility:hidden!important;}}
iframe[height="0"]{{position:absolute!important;width:0!important;height:0!important;opacity:0!important;pointer-events:none!important;border:0!important;}}
html,body,[class*="css"],.stApp{{font-family:'Inter',system-ui,sans-serif;-webkit-font-smoothing:antialiased;}}
.block-container{{max-width:820px;padding-top:1.5rem;padding-bottom:5rem;}}
h1{{font-weight:700;letter-spacing:-.025em;}}h2,h3{{font-weight:600;letter-spacing:-.02em;}}p{{line-height:1.65;}}
code,pre,.kp-mono{{font-family:'JetBrains Mono',monospace!important;font-variant-numeric:tabular-nums;}}
.kp-muted{{color:var(--kp-mt);}}.kp-eye{{font-size:.72rem;font-weight:700;letter-spacing:.09em;text-transform:uppercase;color:var(--kp-mt);}}
button[kind="primary"],[data-testid="stBaseButton-primary"],[data-testid="stFormSubmitButton"] button[kind="primary"]{{background-color:#4f46e5!important;border-color:#4f46e5!important;color:#fff!important;}}
button[kind="primary"]:hover,[data-testid="stBaseButton-primary"]:hover,[data-testid="stFormSubmitButton"] button[kind="primary"]:hover{{background-color:#4338ca!important;border-color:#4338ca!important;}}
.stButton>button,.stFormSubmitButton>button{{border-radius:10px;font-weight:600;}}
[data-testid="stVerticalBlockBorderWrapper"]{{border-radius:14px!important;border-color:var(--kp-bd)!important;}}
.stTextInput input,.stNumberInput input,.stTextArea textarea{{border-radius:10px!important;}}
[data-testid="stFileUploader"] section{{border-radius:12px;border-style:dashed!important;}}
[data-testid="stHorizontalBlock"]:has(.kp-nav-anchor){{flex-direction:row!important;flex-wrap:nowrap!important;align-items:center!important;gap:8px!important;}}
[data-testid="stHorizontalBlock"]:has(.kp-nav-anchor)>div{{min-width:0!important;}}
a[data-testid="stPageLink-NavLink"]{{padding:7px 12px!important;border-radius:9px!important;text-decoration:none!important;font-weight:600!important;font-size:.88rem!important;border:1px solid var(--kp-bd)!important;justify-content:center!important;}}
a[data-testid="stPageLink-NavLink"]:hover{{border-color:#6366f1!important;background:var(--kp-acs)!important;}}
.kp-brand{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:1.02rem;letter-spacing:-.02em;}}
.kp-bmark{{width:28px;height:28px;border-radius:8px;background:linear-gradient(135deg,#4f46e5,#6366f1);display:inline-flex;align-items:center;justify-content:center;color:#fff;font-size:.8rem;font-weight:800;flex-shrink:0;}}
.kp-bsub{{font-size:.68rem;font-weight:600;color:var(--kp-mt);text-transform:uppercase;letter-spacing:.08em;display:block;margin-top:-2px;}}
.kp-ndiv{{height:1px;background:var(--kp-bd);margin:10px 0 22px;}}
.kp-dark{{background:radial-gradient(circle at 95% 5%,rgba(99,102,241,.28),transparent 52%),linear-gradient(180deg,#090f1d,#0f172a);color:#e2e8f0;border:1px solid rgba(148,163,184,.16);}}
.kp-hero{{border-radius:22px;padding:38px 32px 34px;margin:4px 0 18px;}}
.kp-htop{{display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;margin-bottom:18px;}}
.kp-chip{{display:inline-flex;align-items:center;gap:7px;font-size:.74rem;font-weight:600;color:#cbd5e1;background:rgba(148,163,184,.12);border:1px solid rgba(148,163,184,.22);border-radius:999px;padding:5px 12px;}}
.kp-pulse{{width:7px;height:7px;border-radius:50%;background:#22c55e;box-shadow:0 0 0 3px rgba(34,197,94,.25);}}
.kp-hero h1{{font-size:2.15rem;font-weight:800;line-height:1.15;margin:0 0 12px;color:#f8fafc;}}
.kp-hero p{{font-size:1rem;line-height:1.65;color:#94a3b8;margin:0;max-width:560px;}}
.kp-kpi{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0 4px;}}
.kp-fgrid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:8px;}}
@media(max-width:640px){{.kp-kpi{{grid-template-columns:repeat(2,minmax(0,1fr));}}.kp-fgrid{{grid-template-columns:1fr;}}.kp-hero{{padding:26px 20px;}}.kp-hero h1{{font-size:1.65rem;}}}}
.kp-card{{background:var(--kp-sf);border:1px solid var(--kp-bd);border-radius:14px;padding:16px 18px;}}
.kp-sv{{font-family:'JetBrains Mono',monospace;font-size:1.15rem;font-weight:700;margin-bottom:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
.kp-sl{{font-size:.7rem;color:var(--kp-mt);text-transform:uppercase;letter-spacing:.07em;font-weight:600;}}
.kp-fico{{width:34px;height:34px;border-radius:9px;background:var(--kp-acs);color:#6366f1;display:flex;align-items:center;justify-content:center;font-weight:700;margin-bottom:10px;}}
.kp-bal{{border-radius:18px;padding:24px 26px;margin:12px 0 14px;}}
.kp-bal-top{{display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:12px;}}
.kp-bal-val{{font-family:'JetBrains Mono',monospace;font-size:2.05rem;font-weight:700;color:#f8fafc;margin:4px 0 8px;}}
.kp-uhead{{display:flex;align-items:center;gap:12px;}}
.kp-avatar{{width:42px;height:42px;border-radius:12px;background:linear-gradient(135deg,#4f46e5,#6366f1);color:#fff;font-weight:700;display:flex;align-items:center;justify-content:center;flex-shrink:0;}}
.kp-sec{{font-size:.72rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--kp-mt);margin:24px 0 10px;}}
.kp-steps{{display:flex;flex-direction:column;gap:10px;}}
.kp-step{{display:flex;gap:16px;}}
.kp-sn{{font-family:'JetBrains Mono',monospace;font-size:.85rem;font-weight:700;color:#6366f1;width:28px;flex-shrink:0;padding-top:2px;}}
.kp-empty{{border:1px dashed var(--kp-bd);border-radius:14px;padding:28px 20px;text-align:center;}}
.kp-sep{{height:1px;background:var(--kp-bd);margin:4px 0 8px;}}
.kp-hrow{{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:11px 14px;margin-bottom:8px;}}
.kp-badge{{display:inline-block;font-size:.72rem;font-weight:700;padding:3px 10px;border-radius:999px;white-space:nowrap;}}
.kp-b-ok{{background:rgba(16,185,129,.14);color:#10b981;border:1px solid rgba(16,185,129,.25);}}
.kp-b-warn{{background:rgba(245,158,11,.14);color:#d97706;border:1px solid rgba(245,158,11,.28);}}
.kp-b-err{{background:rgba(239,68,68,.14);color:#ef4444;border:1px solid rgba(239,68,68,.25);}}
.kp-b-info{{background:rgba(99,102,241,.14);color:#6366f1;border:1px solid rgba(99,102,241,.28);}}
.kp-b-muted{{background:rgba(148,163,184,.14);color:var(--kp-mt);border:1px solid rgba(148,163,184,.25);}}
.kp-footer{{margin-top:44px;padding-top:20px;border-top:1px solid var(--kp-bd);display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;font-size:.8rem;color:var(--kp-mt);}}
</style>""", unsafe_allow_html=True)


def navbar():
    c = st.columns([3.2, 1, 1.1], vertical_alignment="center")
    c[0].markdown('<div class="kp-nav-anchor kp-brand"><span class="kp-bmark">KP</span><span>KirimPelanggan<span class="kp-bsub">Partner Portal</span></span></div>', unsafe_allow_html=True)
    with c[1]:
        st.page_link(P_HOME, label="Beranda", use_container_width=True)
    with c[2]:
        u = bool(st.session_state.get("user"))
        st.page_link(P_USER if u else P_AUTH, label="Dashboard" if u else "Masuk", use_container_width=True)
    st.markdown('<div class="kp-ndiv"></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- Halaman Publik
def home_page():
    navbar()
    st.markdown('<div class="kp-dark kp-hero"><div class="kp-htop"><div class="kp-chip"><span class="kp-pulse"></span>SISTEM OPERASIONAL AKTIF · WIB</div><div class="kp-chip">SLA VERIFIKASI 15 MNT – 12 JAM</div></div><h1>Platform Kemitraan Tugas<br>Pelanggan Terkelola.</h1><p>Ambil alokasi kontak eksklusif dari pusat, kerjakan sesuai standar panduan, unggah bukti penyelesaian, dan tarik komisi langsung ke rekening bank atau e-wallet Anda.</p></div>', unsafe_allow_html=True)

    if st.session_state.get("user"):
        if st.button("Buka Dashboard Mitra", type="primary", use_container_width=True):
            st.switch_page(P_USER)
    else:
        c1, c2 = st.columns([2, 1.2])
        if c1.button("Daftar & Mulai Sekarang", type="primary", use_container_width=True):
            st.switch_page(P_AUTH)
        if c2.button("Masuk Akun", use_container_width=True):
            st.switch_page(P_AUTH)

    st.markdown(kpi_grid([(rp_short(RATE), "Komisi / Entri"), (f"{DAILY:,}", "Batas Klaim / Hari"), (rp_short(MIN_WD), "Min. Penarikan"), ("15m–12j", "SLA Verifikasi")]), unsafe_allow_html=True)

    feats = [
        ("01", "Alokasi Eksklusif", "Setiap kontak pelanggan hanya dialokasikan ke satu mitra pada periode aktif untuk mencegah duplikasi tugas."),
        ("02", "Audit & Saldo Real-Time", "Pantau status verifikasi bukti, riwayat kredit komisi, dan saldo siap tarik secara transparan di dashboard."),
        ("03", "Pencairan Multi-Kanal", "Mendukung transfer bank nasional (BCA, BRI, BNI, Mandiri) serta e-wallet (DANA, OVO, GoPay, ShopeePay)."),
    ]
    st.markdown('<div class="kp-sec">Keunggulan Infrastruktur</div><div class="kp-fgrid">' + "".join(
        f'<div class="kp-card"><div class="kp-fico">{n}</div><b>{t}</b><div class="kp-muted" style="font-size:.86rem;margin-top:4px;line-height:1.55;">{d}</div></div>' for n, t, d in feats
    ) + "</div>", unsafe_allow_html=True)

    steps = [
        ("01", "Registrasi & Verifikasi Rekening", "Buat akun mitra dalam 30 detik dan cantumkan rekening bank atau e-wallet tujuan pencairan."),
        ("02", "Ambil Alokasi Tugas Harian", f"Tentukan jumlah kontak yang ingin dikerjakan, maksimal <b>{DAILY:,}</b> entri per hari."),
        ("03", "Eksekusi Sesuai Panduan Operasional", "Gunakan template pesan resmi dari admin dan tandai setiap entri yang tuntas sebagai <b>Selesai</b>."),
        ("04", "Unggah Bukti & Kredit Komisi", f"Kirim bukti pengerjaan. Setelah disetujui, saldo bertambah <b>{rp_short(RATE)}</b> per entri selesai."),
        ("05", "Pencairan Dana", f"Ajukan penarikan mulai <b>{rp_short(MIN_WD)}</b> kapan saja tanpa potongan tersembunyi."),
    ]
    st.markdown('<div class="kp-sec">Alur Kerja Mitra</div><div class="kp-steps">' + "".join(
        f'<div class="kp-card kp-step"><div class="kp-sn">{n}</div><div><b>{t}</b><div class="kp-muted" style="font-size:.9rem;margin-top:4px;line-height:1.6;">{d}</div></div></div>' for n, t, d in steps
    ) + "</div>", unsafe_allow_html=True)

    st.markdown('<div class="kp-sec">Kepatuhan & Kebijakan Data</div><div class="kp-card"><b>Standar Operasional Wajib Mitra</b><ul class="kp-muted" style="margin:8px 0 0;padding-left:18px;font-size:.9rem;line-height:1.7;"><li>Stok harian direset otomatis pukul <b>00.00 WIB</b>. Pastikan tugas selesai ditandai dan bukti dikirim pada hari yang sama.</li><li>Data kontak pelanggan bersifat rahasia. Dilarang menyalin atau membagikannya ke pihak ketiga.</li><li>Hentikan komunikasi segera apabila pelanggan meminta berhenti.</li><li>Pelanggaran berakibat penangguhan permanen dan penahanan saldo.</li></ul></div>', unsafe_allow_html=True)

    st.markdown('<div class="kp-sec">Pertanyaan Umum (FAQ)</div>', unsafe_allow_html=True)
    with st.expander("Berapa lama proses verifikasi bukti pengerjaan?"):
        st.write("Tim operasional meninjau bukti secara berkala dalam 15 menit hingga maksimal 12 jam sejak unggahan diterima.")
    with st.expander("Apakah pengajuan bukti larut malam tetap aman jika melewati jam 00.00 WIB?"):
        st.write("Ya. Sistem menyimpan riwayat klaim dan bukti Anda selama beberapa hari sehingga verifikasi lintas hari tetap akurat.")
    with st.expander("Apa yang terjadi jika pengajuan penarikan ditolak?"):
        st.write("Apabila terjadi kendala rekening atau penolakan administratif, nominal penarikan dikembalikan penuh ke saldo akun Anda.")

    if lic := get("settings.json", {}).get("license", "").strip():
        st.markdown('<div class="kp-sec">Lisensi & Ketentuan Layanan</div>', unsafe_allow_html=True)
        with st.container(border=True):
            st.markdown(lic)

    st.markdown(f'<div class="kp-footer"><span>© {now_wib().year} KirimPelanggan · Partner Operations Platform</span><span>Zona Waktu: WIB (UTC+7)</span></div>', unsafe_allow_html=True)
    if not st.session_state.get("user"):
        bridge_session_to_parent("")


def auth_page():
    if st.session_state.get("user"):
        st.switch_page(P_USER)
    navbar()
    st.markdown('<div style="margin:6px 0 22px;"><div class="kp-eye" style="margin-bottom:8px;">Portal Akses Mitra</div><h1 style="font-size:1.9rem;font-weight:800;margin:0 0 6px;">Masuk atau Daftar Akun</h1><p class="kp-muted" style="font-size:.94rem;margin:0;">Pendaftaran gratis dan langsung aktif tanpa biaya administrasi.</p></div>', unsafe_allow_html=True)
    tab_l, tab_r = st.tabs(["Masuk", "Daftar Mitra Baru"])
    with tab_l:
        with st.form("f_login"):
            u, p = st.text_input("Username"), st.text_input("Password", type="password")
            ok = st.form_submit_button("Masuk ke Dashboard", type="primary", use_container_width=True)
        if ok:
            if err := login(u, p):
                st.error(err)
            else:
                st.switch_page(P_USER)
    with tab_r:
        with st.form("f_reg"):
            u, p, p2 = st.text_input("Username (4–24 karakter huruf/angka)"), st.text_input("Password (minimal 6 karakter)", type="password"), st.text_input("Ulangi Password", type="password")
            ok = st.form_submit_button("Buat Akun Mitra", type="primary", use_container_width=True)
        if ok:
            if p != p2:
                st.error("Konfirmasi password tidak cocok.")
            elif err := register(u, p):
                st.error(err)
            else:
                login(u, p)
                st.switch_page(P_USER)


P_HOME = st.Page(home_page, title="Beranda", url_path="home", default=True)
P_AUTH = st.Page(auth_page, title="Masuk", url_path="masuk")
P_USER = st.Page(user_page, title="Dashboard", url_path="dashboard")
P_ADMIN = st.Page(admin_page, title="Admin", url_path="admin")

inject_css()
sync_session()
st.navigation([P_HOME, P_AUTH, P_USER, P_ADMIN], position="hidden").run()
