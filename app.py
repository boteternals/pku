"""
KirimPelanggan — platform mitra untuk mengerjakan tugas pelanggan.

Runtime     : Streamlit Community Cloud
Storage     : S3-compatible (Hugging Face bucket), JSON per-key
Auth        : PBKDF2-HMAC-SHA256, 120.000 iterasi

Secret (st.secrets):
    S3_ENDPOINT, S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET
    S3_REGION          (opsional, default us-east-1)
    ADMIN_PASSWORD

Format input DB (admin)
-----------------------
Satu entri per baris di textarea:

    081234567890 Budi
    081234567891
    081234567892 Siti

Kolom pertama = nomor, kolom kedua (opsional) = nama. Pemisah spasi atau tab.
Baris diawali `#` diabaikan. Dedupe otomatis berdasarkan nomor.
File `.txt`, `.csv`, atau `.json` juga diterima.

Catatan konsistensi
-------------------
Read-modify-write JSON di S3 tidak atomik. Diasumsikan satu penulis per key
pada satu waktu.
"""
import hashlib
import html as html_lib
import json
import secrets
import uuid
from datetime import datetime, timedelta, timezone

import boto3
import streamlit as st
import streamlit.components.v1 as components
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

# ---------------------------------------------------------------- Konfigurasi
st.set_page_config(page_title="KirimPelanggan", page_icon="📨", layout="centered")

RATE = 1500
MIN_WD = 10000
DAILY = 1000
WIB = timezone(timedelta(hours=7))


def today() -> str:
    return datetime.now(WIB).strftime("%Y-%m-%d")


def rp(n) -> str:
    t = f"{float(n):,.2f}"
    return "Rp" + t.replace(",", "X").replace(".", ",").replace("X", ".")


def rp_short(n) -> str:
    return "Rp" + f"{int(n):,}".replace(",", ".")


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
            elif isinstance(item, dict):
                out.append(item)
            else:
                raise ValueError(f"Tipe tidak didukung: {type(item).__name__}")
        return out
    return parse_db_lines(content.decode("utf-8", errors="replace"))


def entry_nomor(d):
    if isinstance(d, dict):
        return d.get("nomor") or d.get("number") or d.get("phone") or d.get("hp")
    return None


def entry_nama(d):
    if isinstance(d, dict):
        return d.get("nama") or d.get("name")
    return None


def render_entry(col, d):
    nomor = entry_nomor(d)
    nama = entry_nama(d)
    if nomor:
        col.code(str(nomor), language=None)
        if nama:
            col.caption(str(nama))
    else:
        col.code(d if isinstance(d, str) else json.dumps(d, ensure_ascii=False),
                 language=None)


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


# ---------------------------------------------------------------- Klaim
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
        return 0, "Stok entri hari ini habis."
    for x in free:
        assigned[x["id"]] = user
        mine.append({"id": x["id"], "data": x["data"], "status": False, "credited": False})
    put(f"db/{d}/assigned.json", assigned)
    put(claim_key(user), mine)
    return len(free), None


# ---------------------------------------------------------------- Komponen
def is_dark() -> bool:
    try:
        return st.context.theme.type == "dark"
    except Exception:
        return False


def copy_block(text: str, label: str = "Teks dari admin"):
    if not text.strip():
        st.caption("Belum ada teks dari admin.")
        return

    payload = json.dumps(text, ensure_ascii=False).replace("</", "<\\/")
    safe = html_lib.escape(text)
    lines = text.count("\n") + 1
    height = max(150, min(70 + lines * 22 + 50, 560))

    if is_dark():
        bg, fg, border, muted = "#0f172a", "#e2e8f0", "#1e293b", "#94a3b8"
    else:
        bg, fg, border, muted = "#ffffff", "#0f172a", "#e2e8f0", "#64748b"

    components.html(f"""<!DOCTYPE html><html><head><meta charset="utf-8">
<style>
  *{{box-sizing:border-box}}
  body{{margin:0;background:transparent;
       font-family:'Inter',-apple-system,system-ui,sans-serif}}
  .wrap{{background:{bg};border:1px solid {border};border-radius:12px;
        overflow:hidden;color:{fg}}}
  .head{{display:flex;justify-content:space-between;align-items:center;
        padding:10px 14px;border-bottom:1px solid {border};
        font-size:11px;font-weight:600;text-transform:uppercase;
        letter-spacing:.08em;color:{muted}}}
  .btn{{background:transparent;color:{fg};border:1px solid {border};
       border-radius:6px;padding:4px 12px;cursor:pointer;font-size:12px;
       font-weight:500;font-family:inherit;transition:background .15s}}
  .btn:hover{{background:{border}}}
  .btn:active{{transform:scale(.97)}}
  pre{{margin:0;padding:16px 18px;white-space:pre-wrap;word-break:break-word;
      font-family:'JetBrains Mono',ui-monospace,monospace;font-size:13px;
      line-height:1.6}}
</style></head><body>
<div class="wrap">
  <div class="head"><span>{label}</span>
    <button class="btn" id="cp" type="button">Salin</button>
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
    btn.textContent = 'Tersalin';
    setTimeout(() => btn.textContent = 'Salin', 1500);
  }});
</script>
</body></html>""", height=height)


@st.dialog("Rekening penarikan")
def account_dialog():
    st.caption("Isi rekening atau e-wallet tujuan penarikan.")
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

    top = st.columns([4, 1], vertical_alignment="center")
    top[0].markdown(
        f'<div style="font-size:.78rem;font-weight:600;letter-spacing:.08em;'
        f'text-transform:uppercase;color:rgba(128,128,128,1);">Dashboard mitra</div>'
        f'<div style="font-size:1.15rem;font-weight:600;margin-top:2px;">@{user}</div>',
        unsafe_allow_html=True,
    )
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("user", None)
        st.switch_page(P_HOME)

    st.markdown(f"""
    <div class="kp-balance">
      <div class="kp-balance-label">Saldo tersedia</div>
      <div class="kp-balance-value">{rp(me['balance'])}</div>
      <div class="kp-balance-meta">Minimal penarikan {rp_short(MIN_WD)} · tarif {rp_short(RATE)} per entri selesai</div>
    </div>
    """, unsafe_allow_html=True)

    mine = get(claim_key(user), [])
    done = sum(1 for x in mine if x["status"])
    pending = sum(1 for x in mine if x["status"] and not x["credited"])

    s1, s2, s3 = st.columns(3)
    for col, val, lbl in (
        (s1, f"{len(mine)}/{DAILY}", "Klaim hari ini"),
        (s2, str(done), "Selesai"),
        (s3, str(pending), "Menunggu verifikasi"),
    ):
        col.markdown(f"""
        <div class="kp-stat">
          <div class="kp-stat-v">{val}</div>
          <div class="kp-stat-l">{lbl}</div>
        </div>
        """, unsafe_allow_html=True)

    st.write("")
    tab_kerja, tab_wd = st.tabs(["Kerjakan", "Penarikan"])

    with tab_kerja:
        st.markdown('<div class="kp-section-label">1 · Instruksi admin</div>',
                    unsafe_allow_html=True)
        text = get("settings.json", {"text": ""}).get("text", "")
        copy_block(text, "Teks dari admin")

        st.markdown('<div class="kp-section-label">2 · Minta entri</div>',
                    unsafe_allow_html=True)
        sisa = max(1, DAILY - len(mine))
        with st.form("claim_form"):
            n = st.number_input(
                f"Jumlah (maks {DAILY} per hari)", min_value=1,
                max_value=sisa, value=min(10, sisa), step=1,
            )
            submit = st.form_submit_button("Minta", type="primary", use_container_width=True)
        if submit:
            with st.spinner("Menyiapkan…"):
                got, err = request_db(user, int(n))
            if err:
                st.warning(err)
            else:
                st.success(f"{got} entri ditambahkan ke akun Anda.")
                st.rerun()

        st.markdown('<div class="kp-section-label">3 · Daftar entri</div>',
                    unsafe_allow_html=True)
        if not mine:
            st.caption("Belum ada entri. Ajukan lewat formulir di atas.")
        changed = False
        for i, item in enumerate(mine):
            with st.container(border=True):
                left, right = st.columns([4, 1], vertical_alignment="center")
                render_entry(left, item["data"])
                val = right.checkbox(
                    "Selesai" if item["status"] else "Belum",
                    value=item["status"], key=f"st_{item['id']}",
                    disabled=item["credited"],
                )
            if val != item["status"]:
                mine[i]["status"] = val
                changed = True
        if changed:
            put(claim_key(user), mine)
            st.rerun()

        st.markdown('<div class="kp-section-label">4 · Unggah bukti</div>',
                    unsafe_allow_html=True)
        files = st.file_uploader(
            "Unggah foto bukti pengerjaan",
            type=["png", "jpg", "jpeg", "webp"],
            accept_multiple_files=True,
            label_visibility="collapsed",
        )
        if st.button("Kirim bukti", type="primary", disabled=not files,
                     use_container_width=True):
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

    with tab_wd:
        acc = me["account"]
        st.markdown('<div class="kp-section-label">Rekening tujuan</div>',
                    unsafe_allow_html=True)
        if acc:
            st.markdown(f"""
            <div class="kp-callout">
              <div class="kp-callout-title">{acc['type']} · {acc['number']}</div>
              <div style="color:rgba(128,128,128,1);font-size:.92rem;">a.n. {acc['name']}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.caption("Rekening belum didaftarkan.")
        if st.button("Ubah rekening"):
            account_dialog()

        st.markdown('<div class="kp-section-label">Ajukan penarikan</div>',
                    unsafe_allow_html=True)
        with st.form("wd_form"):
            amt = st.number_input(
                f"Jumlah (minimal {rp_short(MIN_WD)})",
                min_value=MIN_WD, step=1000, value=MIN_WD,
            )
            submit = st.form_submit_button("Ajukan penarikan", type="primary",
                                           use_container_width=True)
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
            st.markdown('<div class="kp-section-label">Riwayat</div>',
                        unsafe_allow_html=True)
            for w in reversed(my_wd):
                st.write(f"`{w['time'][:16]}` · **{rp(w['amount'])}** · {w['status']}")


# ---------------------------------------------------------------- Admin
def admin_page():
    if not st.session_state.get("admin"):
        st.markdown("""
        <div style="margin:8px 0 20px;">
          <div style="font-size:.72rem;font-weight:600;letter-spacing:.08em;
               text-transform:uppercase;color:rgba(128,128,128,1);margin-bottom:8px;">Internal</div>
          <h1 style="font-size:1.75rem;font-weight:700;letter-spacing:-.025em;margin:0;">Admin</h1>
        </div>
        """, unsafe_allow_html=True)
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

    top = st.columns([4, 1], vertical_alignment="center")
    top[0].subheader("Dashboard admin")
    if top[1].button("Keluar", use_container_width=True):
        st.session_state.pop("admin", None)
        st.rerun()

    users = get("users.json", {})

    t_db, t_user, t_wd, t_up, t_set, t_home = st.tabs(
        ["Stok DB", "Pengguna", "Penarikan", "Bukti", "Teks", "Beranda"]
    )

    # ----- Stok DB -----
    with t_db:
        d = today()
        pool = get(f"db/{d}/pool.json", [])
        assigned = get(f"db/{d}/assigned.json", {})
        st.caption(
            f"Periode {d} (WIB) · total {len(pool)} · terpakai {len(assigned)} "
            f"· sisa {len(pool) - len(assigned)}"
        )

        st.markdown(
            "**Format** — satu entri per baris. "
            "`nomor` atau `nomor<spasi/tab>nama`. Baris diawali `#` diabaikan."
        )
        raw = st.text_area(
            "Daftar entri",
            height=200,
            placeholder="081234567890 Budi\n081234567891\n081234567892 Siti",
            label_visibility="collapsed",
        )

        up = st.file_uploader(
            "Atau unggah file .txt / .csv / .json",
            type=["txt", "csv", "json"], key="db_up",
        )

        if st.button("Tambahkan ke stok hari ini", type="primary"):
            entries = None
            if up is not None:
                try:
                    entries = parse_db_file(up)
                except Exception as e:
                    st.error(f"File tidak valid: {e}")
            elif raw.strip():
                entries = parse_db_lines(raw)
            else:
                st.warning("Tempel data atau unggah file terlebih dahulu.")

            if entries is not None:
                if not entries:
                    st.warning("Tidak ada entri yang bisa ditambahkan.")
                else:
                    existing_nomor = {
                        entry_nomor(x["data"]) for x in pool if entry_nomor(x["data"])
                    }
                    existing_json = {
                        json.dumps(x["data"], sort_keys=True) for x in pool
                    }
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
                        pool.append({"id": uuid.uuid4().hex[:12], "data": e})
                        added += 1
                    put(f"db/{d}/pool.json", pool)
                    msg = f"{added} entri ditambahkan"
                    if skipped:
                        msg += f" · {skipped} duplikat dilewati"
                    st.success(msg)

    # ----- Pengguna -----
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

    # ----- Penarikan -----
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
                if c[0].button("Sudah dibayar", key=f"p_{w['id']}", type="primary"):
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

    # ----- Bukti -----
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
                if c[0].button("Setujui", key=f"a_{p['id']}", type="primary"):
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

    # ----- Teks -----
    with t_set:
        cfg = get("settings.json", {"text": ""})
        txt = st.text_area("Teks untuk pengguna", value=cfg.get("text", ""), height=200)
        if st.button("Simpan teks", type="primary"):
            cfg["text"] = txt
            put("settings.json", cfg)
            st.success("Tersimpan.")

    # ----- Beranda -----
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"], .stApp {
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
  font-feature-settings: 'cv11', 'ss01';
  -webkit-font-smoothing: antialiased;
}

.block-container { max-width: 740px; padding-top: 2rem; padding-bottom: 4rem; }

h1 { font-weight: 700; letter-spacing: -0.025em; }
h2 { font-weight: 600; letter-spacing: -0.02em; }
h3 { font-weight: 600; letter-spacing: -0.015em; }
p  { line-height: 1.65; }

code, pre, .kp-mono {
  font-family: 'JetBrains Mono', ui-monospace, SFMono-Regular, monospace !important;
}

.stButton > button, .stFormSubmitButton > button {
  border-radius: 8px; font-weight: 500; transition: all .15s ease;
}
.stButton > button[kind="primary"], .stFormSubmitButton > button[kind="primary"] {
  font-weight: 600;
}

a[data-testid="stPageLink-NavLink"] {
  padding: 8px 14px !important;
  border-radius: 8px !important;
  text-decoration: none !important;
  font-weight: 500 !important;
  border: 1px solid transparent !important;
  transition: background .15s ease, border-color .15s ease !important;
}
a[data-testid="stPageLink-NavLink"]:hover {
  background: rgba(128,128,128,.08) !important;
  border-color: rgba(128,128,128,.18) !important;
}

[data-testid="stVerticalBlockBorderWrapper"] { border-radius: 14px !important; }
.stTextInput input, .stNumberInput input, .stTextArea textarea { border-radius: 8px !important; }
[data-testid="stFileUploader"] section {
  border-radius: 10px; border-style: dashed !important;
}

.kp-brand {
  display: flex; align-items: center; gap: 10px;
  font-weight: 700; font-size: 1rem; letter-spacing: -0.02em;
  padding: 8px 0;
}
.kp-brand-dot {
  width: 9px; height: 9px; border-radius: 50%;
  background: #6366f1; box-shadow: 0 0 0 3px rgba(99,102,241,0.18);
}

.kp-hero {
  position: relative;
  background:
    radial-gradient(circle at 100% 0%, rgba(99,102,241,0.28), transparent 55%),
    linear-gradient(180deg, #0b1220 0%, #0f172a 100%);
  color: #e2e8f0;
  border-radius: 20px;
  padding: 44px 36px 40px;
  margin: 8px 0 20px;
  border: 1px solid rgba(148,163,184,0.12);
  overflow: hidden;
}
.kp-hero-badge {
  display: inline-block; font-size: .7rem; font-weight: 600;
  letter-spacing: .1em; text-transform: uppercase; color: #94a3b8;
  border: 1px solid rgba(148,163,184,0.25); border-radius: 999px;
  padding: 4px 10px; margin-bottom: 20px;
}
.kp-hero h1 {
  font-size: 2.25rem; font-weight: 700; line-height: 1.15;
  margin: 0 0 12px; color: #f8fafc; letter-spacing: -.03em;
}
.kp-hero p {
  font-size: 1rem; line-height: 1.6; color: #94a3b8;
  margin: 0; max-width: 500px;
}

.kp-balance {
  background:
    radial-gradient(circle at 100% 0%, rgba(99,102,241,0.22), transparent 55%),
    linear-gradient(180deg, #0b1220 0%, #0f172a 100%);
  color: #e2e8f0;
  border-radius: 18px; padding: 26px 28px 24px;
  margin: 10px 0 16px;
  border: 1px solid rgba(148,163,184,0.12);
}
.kp-balance-label {
  font-size: .7rem; font-weight: 600; letter-spacing: .1em;
  text-transform: uppercase; color: #64748b; margin-bottom: 6px;
}
.kp-balance-value {
  font-family: 'JetBrains Mono', monospace;
  font-size: 2.1rem; font-weight: 600; color: #f8fafc;
  letter-spacing: -.02em; margin-bottom: 10px;
}
.kp-balance-meta { font-size: .82rem; color: #94a3b8; }

.kp-stat {
  background: var(--secondary-background-color, rgba(128,128,128,0.06));
  border: 1px solid rgba(128,128,128,0.15);
  border-radius: 12px; padding: 14px 16px;
}
.kp-stat-v {
  font-family: 'JetBrains Mono', monospace;
  font-size: 1.1rem; font-weight: 600; margin-bottom: 2px;
}
.kp-stat-l {
  font-size: .72rem; color: rgba(128,128,128,1);
  text-transform: uppercase; letter-spacing: .07em; font-weight: 500;
}

.kp-section-label {
  font-size: .7rem; font-weight: 600; letter-spacing: .1em;
  text-transform: uppercase; color: rgba(128,128,128,1);
  margin: 28px 0 12px;
}
.kp-section-label:first-child { margin-top: 12px; }

.kp-steps { display: flex; flex-direction: column; gap: 12px; }
.kp-step {
  display: flex; gap: 20px;
  background: var(--secondary-background-color, rgba(128,128,128,0.05));
  border: 1px solid rgba(128,128,128,0.15);
  border-radius: 14px; padding: 20px 22px;
}
.kp-step-n {
  font-family: 'JetBrains Mono', monospace;
  font-size: .85rem; font-weight: 600; color: #6366f1;
  flex-shrink: 0; width: 28px; padding-top: 2px;
}
.kp-step-t { font-weight: 600; margin-bottom: 4px; font-size: .98rem; }
.kp-step-d {
  color: rgba(128,128,128,1); font-size: .92rem; line-height: 1.6;
}
.kp-step-d b { color: inherit; font-weight: 600; }

.kp-callout {
  border-radius: 14px; padding: 18px 22px; margin: 8px 0 4px;
  border: 1px solid rgba(128,128,128,0.15);
  background: var(--secondary-background-color, rgba(128,128,128,0.05));
}
.kp-callout-title { font-weight: 600; margin-bottom: 8px; font-size: .92rem; }
.kp-callout ul {
  margin: 0; padding-left: 18px; font-size: .92rem;
  line-height: 1.7; color: rgba(128,128,128,1);
}
.kp-callout li { margin-bottom: 6px; }
.kp-callout li:last-child { margin-bottom: 0; }

.kp-nav-divider {
  height: 1px; background: rgba(128,128,128,0.15); margin: 6px 0 24px;
}
</style>
""", unsafe_allow_html=True)


def navbar():
    c = st.columns([3, 1, 1], vertical_alignment="center")
    c[0].markdown(
        '<div class="kp-brand"><span class="kp-brand-dot"></span>KirimPelanggan</div>',
        unsafe_allow_html=True,
    )
    with c[1]:
        st.page_link(P_HOME, label="Beranda")
    with c[2]:
        if st.session_state.get("user"):
            st.page_link(P_USER, label="Dashboard")
        else:
            st.page_link(P_AUTH, label="Masuk")
    st.markdown('<div class="kp-nav-divider"></div>', unsafe_allow_html=True)


# ---------------------------------------------------------------- Halaman publik
def home_page():
    navbar()

    st.markdown("""
    <div class="kp-hero">
      <div class="kp-hero-badge">Platform mitra</div>
      <h1>Kerjakan tugas pelanggan.<br>Dibayar per selesai chat</h1>
      <p>Ambil pekerjaan dari admin, selesaikan, unggah bukti. Saldo masuk setelah
         diverifikasi dalam waktu 15 menit hingga 12 jam. Tarik kapan saja ke rekening atau e-wallet Anda.</p>
    </div>
    """, unsafe_allow_html=True)

    if st.session_state.get("user"):
        if st.button("Buka dashboard", type="primary", use_container_width=True):
            st.switch_page(P_USER)
    else:
        if st.button("Masuk atau daftar sekarang", type="primary", use_container_width=True):
            st.switch_page(P_AUTH)

    st.write("")
    s1, s2, s3 = st.columns(3)
    for col, val, lbl in (
        (s1, rp_short(RATE), "Per chat selesai"),
        (s2, str(DAILY), "Klaim maks / hari"),
        (s3, rp_short(MIN_WD), "Minimum penarikan"),
    ):
        col.markdown(f"""
        <div class="kp-stat">
          <div class="kp-stat-v">{val}</div>
          <div class="kp-stat-l">{lbl}</div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Alur kerja</div>', unsafe_allow_html=True)
    st.markdown(f"""
    <div class="kp-steps">
      <div class="kp-step">
        <div class="kp-step-n">01</div>
        <div>
          <div class="kp-step-t">Buat akun & daftarkan rekening</div>
          <div class="kp-step-d">Isi username dan password. Saat pertama masuk, cantumkan
            rekening bank atau e-wallet tujuan penarikan.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">02</div>
        <div>
          <div class="kp-step-t">Minta entri dari stok harian</div>
          <div class="kp-step-d">Tentukan jumlah, maksimal <b>{DAILY}</b> per hari. Setiap entri
            bersifat eksklusif — hanya terkirim ke satu pengguna.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">03</div>
        <div>
          <div class="kp-step-t">Kerjakan sesuai instruksi</div>
          <div class="kp-step-d">Ikuti teks dari admin. Tandai entri sebagai <b>Selesai</b>
            di dashboard setelah pekerjaan tuntas.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">04</div>
        <div>
          <div class="kp-step-t">Unggah bukti pengerjaan</div>
          <div class="kp-step-d">Kirim foto bukti. Setelah admin menyetujui, saldo bertambah
            <b>{rp_short(RATE)}</b> untuk setiap entri berstatus selesai.</div>
        </div>
      </div>
      <div class="kp-step">
        <div class="kp-step-n">05</div>
        <div>
          <div class="kp-step-t">Cairkan ke rekening</div>
          <div class="kp-step-d">Ajukan penarikan minimal <b>{rp_short(MIN_WD)}</b>. Admin
            memproses transfer ke rekening yang Anda daftarkan.</div>
        </div>
      </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Ketentuan</div>', unsafe_allow_html=True)
    st.markdown("""
    <div class="kp-callout">
      <div class="kp-callout-title">Baca sebelum memulai</div>
      <ul>
        <li>Stok dan klaim direset otomatis setiap pukul <b>00.00 WIB</b>.
            Selesaikan pekerjaan dan unggah bukti pada hari yang sama.</li>
        <li>Data pelanggan bersifat rahasia. Dilarang menyalin, menyimpan, atau
            membagikannya ke pihak lain.</li>
        <li>Hentikan komunikasi bila pelanggan meminta berhenti.</li>
        <li>Pelanggaran berakibat pemblokiran akun dan penahanan saldo.</li>
      </ul>
    </div>
    """, unsafe_allow_html=True)

    st.markdown('<div class="kp-section-label">Lisensi</div>', unsafe_allow_html=True)
    lic = get("settings.json", {}).get("license", "").strip()
    if lic:
        with st.container(border=True):
            st.markdown(lic)
    else:
        st.caption("Belum diisi admin.")


def auth_page():
    if st.session_state.get("user"):
        st.switch_page(P_USER)
    navbar()

    st.markdown("""
    <div style="margin: 8px 0 24px;">
      <div style="font-size:.7rem;font-weight:600;letter-spacing:.1em;
           text-transform:uppercase;color:rgba(128,128,128,1);margin-bottom:10px;">
        Akun mitra</div>
      <h1 style="font-size:1.9rem;font-weight:700;letter-spacing:-.025em;margin:0 0 8px;">
        Masuk atau daftar</h1>
      <p style="color:rgba(128,128,128,1);font-size:.95rem;margin:0;line-height:1.6;">
        Butuh sekitar 30 detik untuk memulai. Tidak ada biaya pendaftaran.</p>
    </div>
    """, unsafe_allow_html=True)

    tab_l, tab_r = st.tabs(["Masuk", "Daftar baru"])

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
