# app.py
import streamlit as st
import pandas as pd
import re
import io
import sqlite3
import xml.etree.ElementTree as ET
import pdfplumber
from datetime import datetime
from cryptography.fernet import Fernet
import base64
import os

# ------------------------------
# Configuração Streamlit
# ------------------------------
st.set_page_config(page_title="Extrator de NF-e Seguro", layout="wide")

DB_PATH = "nfe_local_encrypted.db"
MAX_LOGIN_ATTEMPTS = 5
AES_KEY_FILE = "aes_key.key"

# ------------------------------
# Funções de criptografia AES
# ------------------------------
def gerar_chave_aes(senha: str):
    key = base64.urlsafe_b64encode(senha.encode("utf-8").ljust(32)[:32])
    return Fernet(key)

def salvar_chave_local(key: bytes):
    with open(AES_KEY_FILE, "wb") as f:
        f.write(key)

def carregar_chave_local():
    if os.path.exists(AES_KEY_FILE):
        return open(AES_KEY_FILE, "rb").read()
    return None

# ------------------------------
# Funções de extração e formatação
# ------------------------------
def limpar_chave(texto):
    if not texto:
        return ""
    s = re.sub(r"\D", "", texto)
    return s if len(s) == 44 else ""

def formatar_valor_br(valor):
    try:
        v = float(str(valor).replace(".", "").replace(",", "."))
        s = f"{v:,.2f}"
        return s.replace(",", "X").replace(".", ",").replace("X", ".")
    except:
        return "" if pd.isna(valor) else str(valor)

def localizar_placas(texto):
    if not texto:
        return ""
    t = texto.upper()
    pat = r"[A-Z]{3}[0-9]{4}|[A-Z]{3}[0-9][A-Z][0-9]{2}"
    achados = re.findall(pat, t)
    seen = set()
    placas = []
    for p in achados:
        if p not in seen:
            seen.add(p)
            placas.append(p)
    return ", ".join(placas)

def extrair_texto_pdf_bytes(bts):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(bts)) as pdf:
            for p in pdf.pages:
                text += "\n" + (p.extract_text() or "")
    except:
        try:
            text = bts.decode("latin-1", errors="ignore")
        except:
            text = ""
    return text

# ------------------------------
# Extração XML/PDF
# ------------------------------
def extract_from_xml_bytes(bts):
    try:
        root = ET.fromstring(bts)
    except:
        return {"error": "XML inválido"}

    texto = ET.tostring(root, encoding="utf-8", method="text").decode("utf-8")
    # Chave de acesso
    chave = ""
    for elem in root.iter():
        tag = elem.tag
        if tag.lower().endswith("infnfe") and "Id" in elem.attrib:
            chave = limpar_chave(elem.attrib.get("Id", ""))
            if chave:
                break
    if not chave:
        m = re.search(r"\d{44}", texto)
        if m:
            chave = limpar_chave(m.group(0))
    # Data
    data = ""
    m = re.search(r"\d{4}-\d{2}-\d{2}", texto)
    if m:
        data = m.group(0)
    else:
        m2 = re.search(r"\d{2}/\d{2}/\d{4}", texto)
        if m2:
            try:
                data = datetime.strptime(m2.group(0), "%d/%m/%Y").date().isoformat()
            except:
                data = m2.group(0)
    # Valor
    v = ""
    m = re.search(r"vNF[^0-9]*([\d\.,]+)", texto, flags=re.IGNORECASE)
    if m:
        v = formatar_valor_br(m.group(1))
    else:
        m2 = re.search(r"R\$[^\d]*([\d\.,]+)", texto)
        if m2:
            v = formatar_valor_br(m2.group(1))
    # Peso
    p = ""
    m = re.search(r"(peso[^\d]*)([\d\.,]+)", texto, flags=re.IGNORECASE)
    if m:
        p = formatar_valor_br(m.group(2))
    else:
        m2 = re.search(r"([\d\.,]+)\s?kg", texto, flags=re.IGNORECASE)
        if m2:
            p = formatar_valor_br(m2.group(1))
    # CEPs
    ceps = re.findall(r"\d{5}-\d{3}|\d{8}", texto)
    cep_origem = ceps[0] if len(ceps) > 0 else ""
    cep_destino = ceps[1] if len(ceps) > 1 else ""
    # Municípios
    muns = re.findall(r"(?:Município|xMun)[^\w]*([\w\s]+)", texto)
    municipio_origem = muns[0] if len(muns) > 0 else ""
    municipio_destino = muns[1] if len(muns) > 1 else ""
    # Número NF
    nNF = ""
    m = re.search(r"\bnNF\b[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        nNF = m.group(1)
    # Docnun
    docnun = ""
    m = re.search(r"docnun[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        docnun = m.group(1)
    # Placas
    placas = localizar_placas(texto)

    return {
        "arquivo": "",
        "chave_acesso": chave,
        "data": data,
        "valor": v,
        "peso": p,
        "cep_origem": cep_origem,
        "cep_destino": cep_destino,
        "municipio_origem": municipio_origem,
        "municipio_destino": municipio_destino,
        "nNF": nNF,
        "docnun": docnun,
        "placas": placas
    }

def extract_from_pdf_bytes(bts):
    texto = extrair_texto_pdf_bytes(bts)
    # Reaproveitar função XML para estrutura
    return extract_from_xml_bytes(texto.encode('utf-8'))

# ------------------------------
# Processamento múltiplos arquivos
# ------------------------------
def processar_arquivos(files):
    rows = []
    for nome, conteudo in files:
        ext = nome.lower().split('.')[-1]
        if ext == "xml":
            info = extract_from_xml_bytes(conteudo)
        elif ext == "pdf":
            info = extract_from_pdf_bytes(conteudo)
        else:
            try:
                txt = conteudo.decode('latin-1', errors='ignore')
                info = {
                    "arquivo": nome,
                    "chave_acesso": limpar_chave(re.search(r"\d{44}", txt).group(0)) if re.search(r"\d{44}", txt) else "",
                    "data": "",
                    "valor": "",
                    "peso": "",
                    "cep_origem": "",
                    "cep_destino": "",
                    "municipio_origem": "",
                    "municipio_destino": "",
                    "nNF": "",
                    "docnun": "",
                    "placas": localizar_placas(txt)
                }
            except:
                info = {"arquivo": nome, "error": "extensão não suportada"}
        info["arquivo"] = nome
        rows.append(info)
    df = pd.DataFrame(rows)
    expected = ["arquivo","chave_acesso","data","valor","peso","cep_origem","cep_destino",
                "municipio_origem","municipio_destino","nNF","docnun","placas"]
    for c in expected:
        if c not in df.columns:
            df[c] = ""
    return df[expected]

# ------------------------------
# Banco SQLite criptografado
# ------------------------------
def criar_banco_local(path=DB_PATH):
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        arquivo TEXT,
        chave_acesso TEXT UNIQUE,
        data TEXT,
        valor TEXT,
        peso TEXT,
        cep_origem TEXT,
        cep_destino TEXT,
        municipio_origem TEXT,
        municipio_destino TEXT,
        nNF TEXT,
        docnun TEXT,
        placas TEXT,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def salvar_no_banco_local(df, fernet, path=DB_PATH):
    if df is None or df.empty:
        return
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    for _, r in df.iterrows():
        try:
            valor_encrypted = fernet.encrypt(r.get("valor","").encode()).decode()
            peso_encrypted = fernet.encrypt(r.get("peso","").encode()).decode()
            docnun_encrypted = fernet.encrypt(r.get("docnun","").encode()).decode()
            placas_encrypted = fernet.encrypt(r.get("placas","").encode()).decode()
            chave_encrypted = fernet.encrypt(r.get("chave_acesso","").encode()).decode()
            cursor.execute("""
            INSERT INTO notas 
            (arquivo, chave_acesso, data, valor, peso, cep_origem, cep_destino, 
             municipio_origem, municipio_destino, nNF, docnun, placas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.get("arquivo",""),
                chave_encrypted,
                r.get("data",""),
                valor_encrypted,
                peso_encrypted,
                r.get("cep_origem",""),
                r.get("cep_destino",""),
                r.get("municipio_origem",""),
                r.get("municipio_destino",""),
                r.get("nNF",""),
                docnun_encrypted,
                placas_encrypted
            ))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ------------------------------
# Login/Criptografia
# ------------------------------
if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

senha_input = st.text_input("Senha mestra:", type="password")

if st.button("Entrar"):
    st.session_state.login_attempts += 1
    if st.session_state.login_attempts > MAX_LOGIN_ATTEMPTS:
        st.error("Máximo de tentativas excedido. Contate o administrador.")
    else:
        key_local = carregar_chave_local()
        if key_local:
            fernet = Fernet(key_local)
            st.session_state.fernet = fernet
            st.session_state.logged_in = True
        else:
            fernet = gerar_chave_aes(senha_input)
            salvar_chave_local(fernet._signing_key + fernet._encryption_key)
            st.session_state.fernet = fernet
            st.session_state.logged_in = True
        st.success("Login realizado!")

if not st.session_state.logged_in:
    st.stop()

# ------------------------------
# Interface principal
# ------------------------------
st.title("📄 Extrator de NF-e Seguro e Bonito")
criar_banco_local()

uploaded_files = st.file_uploader("Envie XML/PDF (múltiplos permitidos)", accept_multiple_files=True)

if uploaded_files:
    files_list = [(f.name, f.getvalue()) for f in uploaded_files]
    st.info(f"{len(files_list)} arquivo(s) enviados. Processando...")
    df_novo = processar_arquivos(files_list)
    st.subheader("Novas notas extraídas")
    st.dataframe(df_novo.style.highlight_max(subset=["valor","peso"], color="lightgreen"))

    salvar_no_banco_local(df_novo, st.session_state.fernet)

# ------------------------------
# Exportação CSV descriptografado
# ------------------------------
if st.button("Exportar CSV (dados descriptografados)"):
    conn = sqlite3.connect(DB_PATH)
    df_db = pd.read_sql_query("SELECT * FROM notas ORDER BY criado_em DESC", conn)
    conn.close()
    fernet = st.session_state.fernet
    for col in ["chave_acesso","valor","peso","docnun","placas"]:
        df_db[col] = df_db[col].apply(lambda x: fernet.decrypt(x.encode()).decode() if x else "")
    csv_bytes = df_db.to_csv(index=False).encode()
    st.download_button("Baixar CSV", data=csv_bytes, file_name="notas_descriptografadas.csv", mime="text/csv")

# ------------------------------
# Estatísticas visuais
# ------------------------------
conn = sqlite3.connect(DB_PATH)
df_hist = pd.read_sql_query("SELECT * FROM notas ORDER BY criado_em DESC LIMIT 200", conn)
conn.close()
fernet = st.session_state.fernet
for col in ["chave_acesso","valor","peso","docnun","placas"]:
    df_hist[col] = df_hist[col].apply(lambda x: fernet.decrypt(x.encode()).decode() if x else "")

if not df_hist.empty:
    total_notas = len(df_hist)
    total_valor = df_hist["valor"].replace(",", ".", regex=True).astype(float).sum()
    total_peso = df_hist["peso"].replace(",", ".", regex=True).astype(float).sum()
    col1, col2, col3 = st.columns(3)
    col1.metric("Total de Notas", total_notas)
    col2.metric("Valor Total (R$)", f"{total_valor:,.2f}")
    col3.metric("Peso Total (kg)", f"{total_peso:,.2f}")
    st.subheader("Últimas 200 notas (descriptografadas)")
    st.dataframe(df_hist.style.highlight_max(subset=["valor","peso"], color="lightblue"))