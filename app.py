import hashlib, json, secrets, uuid
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st
from botocore.config import Config
from botocore.exceptions import ClientError

st.set_page_config(page_title="KirimPelanggan", page_icon="📨", layout="centered")

RATE = 1500      # Rp per DB selesai
MIN_WD = 10000   # minimal penarikan
DAILY = 100      # batas Minta DB per user per hari
WIB = timezone(timedelta(hours=7))


def today():
    return datetime.now(WIB).strftime("%Y-%m-%d")


def rp(n):
    return "Rp{:,.0f}".format(n).replace(",", ".")


# ---------------- Storage (bucket S3 Hugging Face) ----------------
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


BUCKET = st.secrets["S3_BUCKET"].strip().replace("s3://", "").strip("/")
if "/" in BUCKET:
    st.error("S3_BUCKET harus nama bucket saja, tanpa garis miring.")
    st.stop()


def get(key, default):
    try:
        body = client().get_object(Bucket=BUCKET, Key=key)["Body"].read()
        return json.loads(body)
    except ClientError:
        return default


def put(key, obj):
    client().put_object(
        Bucket=BUCKET, Key=key,
        Body=json.dumps(obj, ensure_ascii=False).encode(),
        ContentType="application/json",
    )


def get_bytes(key):
    try:
        return client().get_object(Bucket=BUCKET, Key=key)["Body"].read()
    except ClientError:
        return None


@st.cache_data(ttl=3600)
def cleanup(day):
    """Hapus DB & klaim hari sebelumnya (reset jam 00.00 WIB)."""
    for prefix in ("db/", "claims/"):
        token = None
        while True:
            kw = {"Bucket": BUCKET, "Prefix": prefix}
            if token:
                kw["ContinuationToken"] = token
            r = client().list_objects_v2(**kw)
            for o in r.get("Contents", []):
                parts = o["Key"].split("/")
                if len(parts) > 1 and parts[1] != day:
                    client().delete_object(Bucket=BUCKET, Key=o["Key"])
            if not r.get("IsTruncated"):
                break
            token = r["NextContinuationToken"]
    return True


try:
    client().list_objects_v2(Bucket=BUCKET, MaxKeys=1)
except ClientError as e:
    err = e.response.get("Error", {})
    st.error(f"S3 error: {err.get('Code')} - {err.get('Message')}")
    st.stop()

cleanup(today())


# ---------------- Auth ----------------
def hash_pw(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 120000).hex()


def register(username, pw):
    users = get("users.json", {})
    u = username.strip().lower()
    if not u.isalnum() or len(u) < 4:
        return "Username minimal 4 karakter, huruf/angka saja."
    if len(pw) < 6:
        return "Password minimal 6 karakter."
    if u in users:
        return "Username sudah dipakai."
    salt = secrets.token_hex(16)
    users[u] = {"salt": salt, "pw": hash_pw(pw, salt), "balance": 0,
                "account": None, "banned": False,
                "created": datetime.now(WIB).isoformat()}
    put("users.json", users)
    return None


def login(username, pw):
    users = get("users.json", {})
    u = users.get(username.strip().lower())
    if not u or hash_pw(pw, u["salt"]) != u["pw"]:
        return "Username atau password salah."
    if u.get("banned"):
        return "Akun diblokir. Hubungi admin."
    st.session_state.user = username.strip().lower()
    return None


# ---------------- Dialog rekening ----------------
@st.dialog("Daftarkan Rekening Penarikan")
def account_dialog():
    st.write("Isi rekening/e-wallet untuk proses withdraw.")
    kind = st.selectbox("Tujuan", ["DANA", "OVO", "GoPay", "ShopeePay", "BCA", "BRI", "BNI", "Mandiri", "Lainnya"])
    num = st.text_input("Nomor rekening / e-wallet")
    name = st.text_input("Atas nama")
    if st.button("Simpan", type="primary"):
        if not num.strip() or not name.strip():
            st.error("Lengkapi semua kolom.")
            return
        users = get("users.json", {})
        users[st.session_state.user]["account"] = {"type": kind, "number": num.strip(), "name": name.strip()}
        put("users.json", users)
        st.rerun()


# ---------------- Klaim DB ----------------
def claim_key(user):
    return f"claims/{today()}/{user}.json"


def request_db(user, n):
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


# ---------------- Halaman user ----------------
def user_page():
    user = st.session_state.user
    users = get("users.json", {})
    me = users.get(user)
    if not me or me.get("banned"):
        st.session_state.pop("user")
        st.rerun()
    if not me.get("account"):
        account_dialog()

    top = st.columns([3, 1])
    top[0].subheader(f"Halo, {user}")
    if top[1].button("Keluar"):
        st.session_state.pop("user")
        st.rerun()

    st.metric("Saldo saat ini", rp(me["balance"]))

    # Minta DB
    n = st.number_input("Minta DB", min_value=1, max_value=DAILY, value=10, step=1)
    if st.button("Minta", type="primary"):
        got, err = request_db(user, int(n))
        if err:
            st.warning(err)
        else:
            st.success(f"{got} DB ditambahkan.")
        if got:
            st.rerun()

    # Teks dari admin
    settings = get("settings.json", {"text": ""})
    st.markdown("**Teks**")
    st.code(settings.get("text", "") or "(belum diisi admin)", language=None)

    # Daftar DB
    mine = get(claim_key(user), [])
    st.markdown(f"**DB hari ini ({len(mine)}/{DAILY})**")
    changed = False
    for i, item in enumerate(mine):
        c = st.columns([4, 2])
        d = item["data"]
        c[0].write(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False))
        val = c[1].checkbox("Selesai" if item["status"] else "Belum Selesai",
                            value=item["status"], key=f"st_{item['id']}",
                            disabled=item["credited"])
        if val != item["status"]:
            mine[i]["status"] = val
            changed = True
    if changed:
        put(claim_key(user), mine)
        st.rerun()

    # Upload bukti
    st.markdown("**Upload foto bukti**")
    files = st.file_uploader("Foto bukti", type=["png", "jpg", "jpeg", "webp"], accept_multiple_files=True)
    if st.button("Kirim bukti") and files:
        proofs = get("proofs.json", [])
        for f in files:
            ext = f.name.rsplit(".", 1)[-1].lower()
            key = f"proofs/{today()}/{user}-{uuid.uuid4().hex[:8]}.{ext}"
            client().put_object(Bucket=BUCKET, Key=key, Body=f.getvalue())
            proofs.append({"id": uuid.uuid4().hex, "user": user, "date": today(),
                           "key": key, "status": "pending",
                           "time": datetime.now(WIB).isoformat()})
        put("proofs.json", proofs)
        st.success("Bukti terkirim, menunggu verifikasi admin.")

    # Withdraw
    st.divider()
    st.markdown("**Withdraw**")
    acc = me["account"]
    if acc:
        st.caption(f"Tujuan: {acc['type']} {acc['number']} a.n. {acc['name']}")
    if st.button("Ubah rekening"):
        account_dialog()
    amt = st.number_input(f"Jumlah (minimal {rp(MIN_WD)})", min_value=0, step=1000, value=MIN_WD)
    if st.button("Ajukan WD"):
        users = get("users.json", {})
        bal = users[user]["balance"]
        if amt < MIN_WD:
            st.error(f"Minimal WD {rp(MIN_WD)}.")
        elif amt > bal:
            st.error("Saldo tidak cukup.")
        elif not users[user]["account"]:
            st.error("Daftarkan rekening dulu.")
        else:
            users[user]["balance"] = bal - amt
            put("users.json", users)
            wd = get("wd.json", [])
            wd.append({"id": uuid.uuid4().hex, "user": user, "amount": int(amt),
                       "account": users[user]["account"], "status": "pending",
                       "time": datetime.now(WIB).isoformat()})
            put("wd.json", wd)
            st.success("Pengajuan WD dikirim.")
            st.rerun()
    my_wd = [w for w in get("wd.json", []) if w["user"] == user][-10:]
    for w in reversed(my_wd):
        st.write(f"{w['time'][:16]} — {rp(w['amount'])} — {w['status']}")


# ---------------- Halaman admin ----------------
def admin_page():
    top = st.columns([3, 1])
    top[0].subheader("Dashboard Admin")
    if top[1].button("Keluar"):
        st.session_state.pop("admin")
        st.rerun()

    t_db, t_user, t_wd, t_up, t_set = st.tabs(["Isi DB", "User", "WD", "Upload", "Teks"])

    with t_db:
        d = today()
        pool = get(f"db/{d}/pool.json", [])
        assigned = get(f"db/{d}/assigned.json", {})
        st.write(f"Tanggal {d} (WIB): total {len(pool)}, terpakai {len(assigned)}, sisa {len(pool) - len(assigned)}")
        raw = st.text_area("Tempel JSON (list string/objek)", height=150,
                           placeholder='["item1", "item2"] atau [{"nama":"A"}]')
        up = st.file_uploader("atau upload file .json", type=["json"])
        if st.button("Tambahkan ke stok hari ini"):
            try:
                data = json.loads(up.getvalue()) if up else json.loads(raw)
                assert isinstance(data, list)
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
                st.success(f"{added} item ditambahkan (duplikat dilewati).")
            except Exception as e:
                st.error(f"JSON tidak valid: {e}")

    users = get("users.json", {})
    with t_user:
        st.caption(f"Total user: {len(users)}")
        for u, v in users.items():
            with st.expander(f"{u} — {rp(v['balance'])}{' (BLOKIR)' if v.get('banned') else ''}"):
                st.write(f"Daftar: {v['created'][:16]}")
                st.write(f"Rekening: {v['account']}")
                mine = get(claim_key(u), [])
                done = sum(1 for x in mine if x["status"])
                st.write(f"Hari ini: diminta {len(mine)}, selesai {done}")
                c = st.columns(3)
                if c[0].button("Blokir/Buka", key=f"b_{u}"):
                    users[u]["banned"] = not v.get("banned")
                    put("users.json", users)
                    st.rerun()
                nb = c[1].number_input("Saldo", value=int(v["balance"]), step=1500, key=f"n_{u}")
                if c[1].button("Set saldo", key=f"s_{u}"):
                    users[u]["balance"] = int(nb)
                    put("users.json", users)
                    st.rerun()
                if c[2].button("Hapus akun", key=f"d_{u}"):
                    users.pop(u)
                    put("users.json", users)
                    st.rerun()

    with t_wd:
        wd = get("wd.json", [])
        for w in reversed(wd):
            if w["status"] != "pending":
                continue
            a = w["account"]
            st.write(f"**{w['user']}** — {rp(w['amount'])} → {a['type']} {a['number']} a.n. {a['name']}")
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
        st.caption("Riwayat: " + ", ".join(f"{w['user']} {rp(w['amount'])} {w['status']}" for w in wd[-10:] if w["status"] != "pending"))

    with t_up:
        proofs = get("proofs.json", [])
        for p in reversed(proofs):
            if p["status"] != "pending":
                continue
            st.write(f"**{p['user']}** — {p['date']}")
            img = get_bytes(p["key"])
            if img:
                st.image(img, width=300)
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
        st.caption(f"Disetujui: {sum(1 for p in proofs if p['status']=='disetujui')}, ditolak: {sum(1 for p in proofs if p['status']=='ditolak')}")

    with t_set:
        s = get("settings.json", {"text": ""})
        txt = st.text_area("Teks untuk user", value=s.get("text", ""), height=200)
        if st.button("Simpan teks"):
            put("settings.json", {"text": txt})
            st.success("Tersimpan.")


# ---------------- Router ----------------
st.title("📨 KirimPelanggan")

if st.session_state.get("admin"):
    admin_page()
elif st.session_state.get("user"):
    user_page()
else:
    tab_l, tab_r, tab_a = st.tabs(["Masuk", "Daftar", "Admin"])
    with tab_l:
        u = st.text_input("Username", key="lu")
        p = st.text_input("Password", type="password", key="lp")
        if st.button("Masuk", type="primary"):
            err = login(u, p)
            st.error(err) if err else st.rerun()
    with tab_r:
        u = st.text_input("Username", key="ru")
        p = st.text_input("Password", type="password", key="rp")
        if st.button("Daftar", type="primary"):
            err = register(u, p)
            if err:
                st.error(err)
            else:
                login(u, p)
                st.rerun()
    with tab_a:
        p = st.text_input("Password admin", type="password", key="ap")
        if st.button("Masuk admin"):
            if secrets.compare_digest(p, st.secrets["ADMIN_PASSWORD"]):
                st.session_state.admin = True
                st.rerun()
            else:
                st.error("Password salah.")

