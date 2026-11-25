"""
KirimPelanggan — platform mitra untuk mengerjakan tugas pelanggan.

Runtime : Streamlit Community Cloud
Penyimpanan : S3-compatible (Hugging Face bucket), JSON per-key
Auth : PBKDF2-HMAC-SHA256, 120k iterasi

Secret yang dibutuhkan (st.secrets):
    S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET
    S3_REGION      (opsional, default us-east-1)
    ADMIN_PASSWORD

Catatan konsistensi
-------------------
Read-modify-write pada JSON di S3 tidak atomik. Aplikasi ini mengasumsikan
satu penulis per key pada satu waktu (pola operasional wajar untuk skala ini).
Untuk skala lebih besar, migrasikan ke DynamoDB/SQLite di volume persisten.
"""
import hashlib, json, secrets, uuid
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------- Konfigurasi
st.set_page_config(page_title="KirimPelanggan", page_icon="📨", layout="centered")

RATE = 1500      # Rp per DB selesai
MIN_WD = 10000   # minimal penarikan
DAILY = 100      # batas klaim per user per hari
WIB = timezone(timedelta(hours=7))


def today() -> str:
    return datetime.now(WIB).strftime("%Y-%m-%d")


def rp(n) -> str:
    t = f"{float(n):,.2f}"
    return "Rp" + t.replace(",", "X").replace(".", ",").replace("X", ".")


# ---------------------------------------------------------------- Storage
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


def get(key, default):
    try:
        body = client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read()
        return json.loads(body)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") in ("NoSuchKey", "404"):
            return default
        raise


def put(key, obj):
    client().put_object(
        Bucket=BUCKET, Key=PREFIX + key,
        Body=json.dumps(obj, ensure_ascii=False).encode(),
        ContentType="application/json",
    )


def get_bytes(key):
    try:
        return client().get_object(Bucket=BUCKET, Key=PREFIX + key)["Body"].read()
    except ClientError:
        return None


@st.cache_data(ttl=3600, show_spinner=False)
def cleanup(day: str) -> bool:
    """Hapus data & klaim hari sebelumnya (reset 00.00 WIB)."""
    for prefix in ("db/", "claims/"):
        token = None
        while True:
            kw = {"Bucket": BUCKET, "Prefix": PREFIX + prefix}
            if token:
                kw["ContinuationToken"] = token
            r = client().list_objects_v2(**kw)
            for o in r.get("Contents", []):
                parts = o["Key"][len(PREFIX):].split("/")
                if len(parts) > 1 and parts[1] != day:
                    client().delete_object(Bucket=BUCKET, Key=o["Key"])
            if not r.get("IsTruncated"):
                break
            token = r["NextContinuationToken"]
    return True


try:
    client().list_objects_v2(Bucket=BUCKET, Prefix=PREFIX, MaxKeys=1)
except (ClientError, BotoCoreError) as e:
    err = getattr(e, "response", {}).get("Error", {"Code": "?", "Message": str(e)})
    st.error(f"Penyimpanan tidak dapat diakses: {err.get('Code')} — {err.get('Message')}")
    st.stop()

cleanup(today())


# ---------------------------------------------------------------- Auth
def hash_pw(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120_000).hex()


def register(username: str, pw: str) -> str | None:
    users = get("users.json", {})
    u = username.strip().lower()
    if not u.isalnum() or len(u) < 4:
        return "Username minimal 4 karakter (huruf/angka)."
    if len(pw) < 6:
        return "Password minimal 6 karakter."
    if u in users:
        return "Username sudah dipakai."
    salt = secrets.token_hex(16)
    users[u] = {
        "salt": salt, "pw": hash_pw(pw, salt), "balance": 0,
        "account": None, "banned": False,
        "created": datetime.now(WIB).isoformat(),
    }
    put("users.json", users)
    return None


def login(username: str, pw: str) -> str | None:
    users = get("users.json", {})
    u = users.get(username.strip().lower())
    if not u or not secrets.compare_digest(hash_pw(pw, u["salt"]), u["pw"]):
        return "Username atau password salah."
    if u.get("banned"):
        return "Akun diblokir. Hubungi admin."
    st.session_state.user = username.strip().lower()
    return None


# ---------------------------------------------------------------- Klaim DB
def claim_key(user: str) -> str:
    return f"claims/{today()}/{user}.json"


def request_db(user: str, n: int) -> tuple[int, str | None]:
    d = today()
    mine = get(claim_key(user), [])
    n = min(n, DAILY - len(mine))
    if n <= 0:
        return 0, "Batas harian tercapai."
    pool = get(f"db/{d}/pool.json", [])
    assigned = get(f"db/{d}/assigned.json", {})
    free = [x for x in pool if x["id"] not in assigned][:n]
    if not free:
        return 0, "Stok DB hari ini habis."
    for x in free:
        assigned[x["id"]] = user
        mine.append({"id": x["id"], "data": x["data"], "status": False, "credited": False})
    put(f"db/{d}/assigned.json", assigned)
    put(claim_key(user), mine)
    return len(free), None


# ---------------------------------------------------------------- Dialog
@st.dialog("Rekening penarikan")
def account_dialog():
    st.caption("Isi rekening atau e-wallet untuk proses withdraw.")
    kind = st.selectbox(
        "Tujuan",
        ["DANA", "OVO", "GoPay", "ShopeePay", "BCA", "BRI", "BNI", "Mandiri", "Lainnya"],
    )
    num = st.text_input("Nomor rekening / e-wallet")
    name = st.text_input("Nama pemilik")
    if st.button("Simpan", type="primary", use_container_width=True):
        if not num.strip() or not name.strip():
            st.error("Lengkapi semua kolom.")
            return
        users = get("users.json", {})
        users[st.session_state.user]["account"] = {
            "type": kind, "number": num.strip(), "name": name.strip(),
        }
        put("users.json", users)
        st.rerun()


# ---------------------------------------------------------------- Halaman user
def user_page():
    if not st.session_state.get("user"):
        st.switch_page(P_AUTH)
    user = st.session_state.user
    users = get("users.json", {})
    me = users.get(user)
    if not me or me.get("banned"):
        st.session_state.pop("user", None)
        st.switch_page(P_AUTH)
    if not me.get("account"):
        account_dialog()

    # Kartu saldo
    with st.container(border=True):
        c1, c2 = st.columns([3, 2])
        c1.caption("SALDO")
        c1.markdown(f"### {rp(me['balance'])}")
        c2.caption("AKUN")
        c2.markdown(f"`@{user}`")
    top = st.columns([3, 1])
    top[0].write(f"Selamat datang, **{user}**.")
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("user", None)
        st.switch_page(P_HOME)

    # Minta DB
    st.subheader("Minta DB")
    with st.form("claim_form"):
        n = st.number_input("Jumlah", min_value=1, max_value=DAILY, value=10, step=1)
        submit = st.form_submit_button("Minta", type="primary", use_container_width=True)
    if submit:
        with st.spinner("Menyiapkan…"):
            got, err = request_db(user, int(n))
        if err:
            st.warning(err)
        else:
            st.success(f"{got} entri ditambahkan.")
            st.rerun()

    # Teks admin
    st.subheader("Teks dari admin")
    text = get("settings.json", {"text": ""}).get("text", "").strip()
    if text:
        st.code(text, language=None)
    else:
        st.caption("Belum ada teks dari admin.")

    # Daftar klaim
    mine = get(claim_key(user), [])
    st.subheader(f"DB hari ini · {len(mine)}/{DAILY}")
    changed = False
    for i, item in enumerate(mine):
        with st.container(border=True):
            left, right = st.columns([4, 2])
            d = item["data"]
            left.code(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False), language=None)
            val = right.checkbox(
                "Selesai" if item["status"] else "Belum selesai",
                value=item["status"], key=f"st_{item['id']}",
                disabled=item["credited"],
            )
        if val != item["status"]:
            mine[i]["status"] = val
            changed = True
    if changed:
        put(claim_key(user), mine)
        st.rerun()

    # Upload bukti
    st.subheader("Bukti pengerjaan")
    files = st.file_uploader(
        "Unggah foto (PNG/JPG/WEBP)",
        type=["png", "jpg", "jpeg", "webp"],
        accept_multiple_files=True,
    )
    if st.button("Kirim bukti", disabled=not files):
        proofs = get("proofs.json", [])
        for f in files:
            ext = f.name.rsplit(".", 1)[-1].lower()
            key = f"proofs/{today()}/{user}-{uuid.uuid4().hex[:8]}.{ext}"
            client().put_object(Bucket=BUCKET, Key=PREFIX + key, Body=f.getvalue())
            proofs.append({
                "id": uuid.uuid4().hex, "user": user, "date": today(),
                "key": key, "status": "pending",
                "time": datetime.now(WIB).isoformat(),
            })
        put("proofs.json", proofs)
        st.success("Bukti terkirim. Menunggu verifikasi admin.")

    # Withdraw
    st.divider()
    st.subheader("Penarikan")
    acc = me["account"]
    if acc:
        st.caption(f"Tujuan: {acc['type']} · {acc['number']} · a.n. {acc['name']}")
    if st.button("Ubah rekening"):
        account_dialog()

    with st.form("wd_form"):
        amt = st.number_input(
            f"Jumlah (minimal {rp(MIN_WD)})",
            min_value=MIN_WD, step=1000, value=MIN_WD,
        )
        submit = st.form_submit_button("Ajukan penarikan", type="primary", use_container_width=True)
    if submit:
        users = get("users.json", {})
        bal = users[user]["balance"]
        if amt > bal:
            st.error("Saldo tidak mencukupi.")
        elif not users[user]["account"]:
            st.error("Daftarkan rekening terlebih dahulu.")
        else:
            users[user]["balance"] = bal - int(amt)
            put("users.json", users)
            wd = get("wd.json", [])
            wd.append({
                "id": uuid.uuid4().hex, "user": user, "amount": int(amt),
                "account": users[user]["account"], "status": "pending",
                "time": datetime.now(WIB).isoformat(),
            })
            put("wd.json", wd)
            st.success("Pengajuan terkirim.")
            st.rerun()

    my_wd = [w for w in get("wd.json", []) if w["user"] == user][-10:]
    if my_wd:
        st.caption("Riwayat penarikan")
        for w in reversed(my_wd):
            st.write(f"{w['time'][:16]} · {rp(w['amount'])} · {w['status']}")


# ---------------------------------------------------------------- Halaman admin
def admin_page():
    if not st.session_state.get("admin"):
        st.subheader("Admin")
        tries = st.session_state.get("admin_tries", 0)
        with st.form("admin_login"):
            p = st.text_input("Password admin", type="password")
            ok = st.form_submit_button("Masuk", type="primary", use_container_width=True)
        if ok:
            if tries >= 5:
                st.error("Terlalu banyak percobaan. Muat ulang halaman.")
            elif secrets.compare_digest(p.encode(), st.secrets["ADMIN_PASSWORD"].encode()):
                st.session_state.admin = True
                st.session_state.admin_tries = 0
                st.rerun()
            else:
                st.session_state.admin_tries = tries + 1
                st.error("Password salah.")
        return

    top = st.columns([3, 1])
    top[0].subheader("Dashboard admin")
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("admin", None)
        st.rerun()

    t_db, t_user, t_wd, t_up, t_set, t_home = st.tabs(
        ["Stok DB", "Pengguna", "Penarikan", "Bukti", "Teks", "Beranda"]
    )

    users = get("users.json", {})

    with t_db:
        d = today()
        pool = get(f"db/{d}/pool.json", [])
        assigned = get(f"db/{d}/assigned.json", {})
        st.caption(
            f"Periode {d} (WIB) · total {len(pool)} · terpakai {len(assigned)} "
            f"· sisa {len(pool) - len(assigned)}"
        )
        raw = st.text_area(
            "Tempel JSON (array string/objek)", height=150,
            placeholder='["item1", "item2"] atau [{"nama":"A"}]',
        )
        up = st.file_uploader("atau unggah file .json", type=["json"])
        if st.button("Tambahkan ke stok hari ini", type="primary"):
            try:
                data = json.loads(up.getvalue()) if up else json.loads(raw)
                if not isinstance(data, list):
                    raise ValueError("Root harus berupa array.")
                seen = {json.dumps(x["data"], sort_keys=True) for x in pool}
                added = 0
                for x in data:
                    k = json.dumps(x, sort_keys=True)
                    if k in seen:
                        continue
                    seen.add(k)
                    pool.append({"id": uuid.uuid4().hex[:12], "data": x})
                    added += 1
                put(f"db/{d}/pool.json", pool)
                st.success(f"{added} entri ditambahkan (duplikat dilewati).")
            except Exception as e:
                st.error(f"JSON tidak valid: {e}")

    with t_user:
        st.caption(f"Total pengguna: {len(users)}")
        for u, v in users.items():
            label = f"{u} · {rp(v['balance'])}" + (" · DIBLOKIR" if v.get("banned") else "")
            with st.expander(label):
                st.write(f"Terdaftar: {v['created'][:16]}")
                st.write(f"Rekening: {v['account'] or '—'}")
                mine = get(claim_key(u), [])
                done = sum(1 for x in mine if x["status"])
                st.write(f"Hari ini: diminta {len(mine)}, selesai {done}")
                c = st.columns(3)
                if c[0].button("Blokir/buka", key=f"b_{u}"):
                    users[u]["banned"] = not v.get("banned")
                    put("users.json", users)
                    st.rerun()
                nb = c[1].number_input(
                    "Saldo", value=int(v["balance"]), step=1500, key=f"n_{u}",
                )
                if c[1].button("Set saldo", key=f"s_{u}"):
                    users[u]["balance"] = int(nb)
                    put("users.json", users)
                    st.rerun()
                if c[2].button("Hapus", key=f"d_{u}"):
                    users.pop(u)
                    put("users.json", users)
                    st.rerun()

    with t_wd:
        wd = get("wd.json", [])
        pending = [w for w in wd if w["status"] == "pending"]
        if not pending:
            st.caption("Tidak ada penarikan menunggu.")
        for w in reversed(pending):
            a = w["account"]
            with st.container(border=True):
                st.write(f"**{w['user']}** · {rp(w['amount'])}")
                st.caption(f"{a['type']} · {a['number']} · a.n. {a['name']}")
                c = st.columns(2)
                if c[0].button("Sudah dibayar", key=f"p_{w['id']}"):
                    w["status"] = "dibayar"
                    put("wd.json", wd)
                    st.rerun()
                if c[1].button("Tolak & kembalikan", key=f"r_{w['id']}"):
                    w["status"] = "ditolak"
                    if w["user"] in users:
                        users[w["user"]]["balance"] += w["amount"]
                        put("users.json", users)
                    put("wd.json", wd)
                    st.rerun()
        st.caption(
            "Riwayat: " + ", ".join(
                f"{w['user']} {rp(w['amount'])} {w['status']}"
                for w in wd[-10:] if w["status"] != "pending"
            )
        )

    with t_up:
        proofs = get("proofs.json", [])
        pending = [p for p in proofs if p["status"] == "pending"]
        if not pending:
            st.caption("Tidak ada bukti menunggu.")
        for p in reversed(pending):
            with st.container(border=True):
                st.write(f"**{p['user']}** · {p['date']}")
                img = get_bytes(p["key"])
                if img:
                    st.image(img, width=320)
                c = st.columns(2)
                if c[0].button("Setujui", key=f"a_{p['id']}"):
                    claims = get(f"claims/{p['date']}/{p['user']}.json", [])
                    n = 0
                    for x in claims:
                        if x["status"] and not x["credited"]:
                            x["credited"] = True
                            n += 1
                    if n and p["user"] in users:
                        users[p["user"]]["balance"] += n * RATE
                        put("users.json", users)
                        put(f"claims/{p['date']}/{p['user']}.json", claims)
                    p["status"] = "disetujui"
                    put("proofs.json", proofs)
                    st.rerun()
                if c[1].button("Tolak", key=f"x_{p['id']}"):
                    p["status"] = "ditolak"
                    put("proofs.json", proofs)
                    st.rerun()
        st.caption(
            f"Disetujui: {sum(1 for p in proofs if p['status'] == 'disetujui')} · "
            f"ditolak: {sum(1 for p in proofs if p['status'] == 'ditolak')}"
        )

    with t_set:
        cfg = get("settings.json", {"text": ""})
        txt = st.text_area("Teks untuk pengguna", value=cfg.get("text", ""), height=200)
        if st.button("Simpan teks", type="primary"):
            cfg["text"] = txt
            put("settings.json", cfg)
            st.success("Tersimpan.")

    with t_home:
        cfg = get("settings.json", {"text": ""})
        lic = st.text_area(
            "Lisensi & ketentuan (Markdown, tampil di Beranda)",
            value=cfg.get("license", ""), height=300,
        )
        if st.button("Simpan lisensi", type="primary"):
            cfg["license"] = lic
            put("settings.json", cfg)
            st.success("Tersimpan.")


# ---------------------------------------------------------------- Tampilan
def inject_css():
    st.markdown("""
<style>
.block-container { max-width: 720px; padding-top: 2rem; }
h1, h2, h3 { letter-spacing: -0.01em; }
.stButton > button, .stFormSubmitButton > button { border-radius: 8px; font-weight: 500; }
div[data-testid="stMetricValue"] { font-size: 1.75rem; }
code { font-size: 0.85rem; }
</style>""", unsafe_allow_html=True)


def navbar():
    c = st.columns(2)
    c[0].page_link(P_HOME, label="Beranda", icon="🏠")
    if st.session_state.get("user"):
        c[1].page_link(P_USER, label="Dashboard", icon="👛")
    else:
        c[1].page_link(P_AUTH, label="Masuk / daftar", icon="🔑")


DOCS = f"""
#### Cara kerja

1. **Daftar & masuk.** Buat akun, lalu isi rekening/e-wallet tujuan penarikan saat pertama masuk.
2. **Minta DB.** Tentukan jumlah (maks {DAILY} per hari). Setiap entri hanya diberikan ke satu pengguna.
3. **Kerjakan.** Ikuti teks yang diberikan admin. Centang entri setelah selesai dikerjakan.
4. **Upload bukti.** Kirim foto bukti. Setelah admin menyetujui, saldo bertambah **{rp(RATE)}** per entri selesai.
5. **Withdraw.** Ajukan penarikan minimal **{rp(MIN_WD)}** ke rekening terdaftar.

#### Ketentuan

- Stok dan klaim direset otomatis setiap pukul **00.00 WIB**. Kerjakan dan unggah bukti pada hari yang sama.
- Data pelanggan bersifat rahasia. Dilarang menyalin, menyimpan, atau membagikannya.
- Hentikan komunikasi bila pelanggan meminta.
- Pelanggaran berakibat pemblokiran akun dan penahanan saldo.
"""


def home_page():
    navbar()
    st.title("KirimPelanggan")
    st.caption("Platform mitra untuk mengerjakan tugas pelanggan.")
    if st.session_state.get("user"):
        st.page_link(P_USER, label="Buka dashboard", icon="👛")
    else:
        st.page_link(P_AUTH, label="Masuk atau daftar", icon="🔑")
    st.divider()
    st.markdown(DOCS)
    st.divider()
    st.subheader("Lisensi")
    lic = get("settings.json", {}).get("license", "").strip()
    st.markdown(lic or "_Belum diisi admin._")


def auth_page():
    if st.session_state.get("user"):
        st.switch_page(P_USER)
    navbar()
    st.title("Masuk ke akun mitra")
    tab_l, tab_r = st.tabs(["Masuk", "Daftar"])

    with tab_l:
        with st.form("f_login"):
            u = st.text_input("Username")
            p = st.text_input("Password", type="password")
            ok = st.form_submit_button("Masuk", type="primary", use_container_width=True)
        if ok:
            err = login(u, p)
            if err:
                st.error(err)
            else:
                st.switch_page(P_USER)

    with tab_r:
        with st.form("f_reg"):
            u = st.text_input("Username (huruf/angka, min. 4)")
            p = st.text_input("Password (min. 6)", type="password")
            p2 = st.text_input("Ulangi password", type="password")
            ok = st.form_submit_button("Buat akun", type="primary", use_container_width=True)
        if ok:
            if p != p2:
                st.error("Password tidak sama.")
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
st.navigation([P_HOME, P_AUTH, P_USER, P_ADMIN], position="hidden").run()
