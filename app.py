# app.py - Extrator de NF-e Seguro e Dinâmico
import streamlit as st
import pandas as pd
import re
import io
import sqlite3
import xml.etree.ElementTree as ET
import pdfplumber
from datetime import datetime
import hashlib

# ===========================
# Configuração da página
# ===========================
st.set_page_config(page_title="Extrator de NF-e", layout="wide")

# ===========================
# Banco de dados local
# ===========================
DB_PATH = "nfe_local.db"  # caminho do banco SQLite

def criar_banco_local(path=DB_PATH):
    """Cria o banco SQLite com tabela de notas e tabela de usuários."""
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    # tabela de notas
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
        nNF TEXT,
        docnun TEXT,
        placas TEXT,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    # tabela de usuários
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        tentativas INTEGER DEFAULT 0,
        bloqueado INTEGER DEFAULT 0
    )
    """)
    conn.commit()
    conn.close()

def hash_senha(senha):
    """Gera hash SHA256 da senha."""
    return hashlib.sha256(senha.encode()).hexdigest()

def cadastrar_usuario(username, senha):
    """Cadastra novo usuário com senha hash."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO usuarios (username, password_hash) VALUES (?,?)",
                       (username, hash_senha(senha)))
        conn.commit()
    except sqlite3.IntegrityError:
        pass  # usuário já existe
    conn.close()

def verificar_login(username, senha):
    """Verifica login, bloqueio e incrementa tentativas."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT password_hash, tentativas, bloqueado FROM usuarios WHERE username=?", (username,))
    row = cursor.fetchone()
    if row is None:
        conn.close()
        return False, "Usuário não encontrado"
    senha_hash, tentativas, bloqueado = row
    if bloqueado:
        conn.close()
        return False, "Conta bloqueada"
    if hash_senha(senha) == senha_hash:
        # reset tentativas
        cursor.execute("UPDATE usuarios SET tentativas=0 WHERE username=?", (username,))
        conn.commit()
        conn.close()
        return True, "Login OK"
    else:
        tentativas += 1
        bloqueado_flag = 1 if tentativas >= 5 else 0
        cursor.execute("UPDATE usuarios SET tentativas=?, bloqueado=? WHERE username=?", (tentativas, bloqueado_flag, username))
        conn.commit()
        conn.close()
        if bloqueado_flag:
            return False, "Conta bloqueada após 5 tentativas"
        else:
            return False, f"Senha incorreta ({tentativas}/5)"

# ===========================
# Funções de extração
# ===========================
def limpar_chave(texto):
    if not texto: return ""
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
    if not texto: return ""
    t = texto.upper()
    pat = r"[A-Z]{3}[0-9]{4}|[A-Z]{3}[0-9][A-Z][0-9]{2}"
    achados = re.findall(pat, t)
    seen = set(); placas = []
    for p in achados:
        if p not in seen: seen.add(p); placas.append(p)
    return ", ".join(placas)

def extrair_texto_pdf_bytes(bts):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(bts)) as pdf:
            for p in pdf.pages: text += "\n" + (p.extract_text() or "")
    except:
        try:
            text = bts.decode("latin-1", errors="ignore")
        except:
            text = ""
    return text

def extract_from_xml_bytes(bts):
    try:
        root = ET.fromstring(bts)
    except:
        return {"error": "XML inválido"}
    texto = ET.tostring(root, encoding="utf-8", method="text").decode("utf-8")
    # Chave
    chave = ""
    for elem in root.iter():
        if elem.tag.lower().endswith("infnfe") and "Id" in elem.attrib:
            chave = limpar_chave(elem.attrib.get("Id",""))
            if chave: break
    if not chave:
        m = re.search(r"\d{44}", texto)
        if m: chave = limpar_chave(m.group(0))
    # Data
    data = ""
    m = re.search(r"\d{4}-\d{2}-\d{2}", texto) or re.search(r"\d{2}/\d{2}/\d{4}", texto)
    if m:
        try:
            if "/" in m.group(0):
                data = datetime.strptime(m.group(0), "%d/%m/%Y").date().isoformat()
            else:
                data = m.group(0)
        except:
            data = m.group(0)
    # Valor
    v = ""
    m = re.search(r"vNF[^0-9]*([\d\.,]+)", texto, flags=re.IGNORECASE) or re.search(r"R\$[^\d]*([\d\.,]+)", texto)
    if m: v = formatar_valor_br(m.group(1))
    # Peso
    p = ""
    m = re.search(r"(peso[^\d]*)([\d\.,]+)", texto, flags=re.IGNORECASE) or re.search(r"([\d\.,]+)\s?kg", texto, flags=re.IGNORECASE)
    if m: p = formatar_valor_br(m.group(2) if len(m.groups())>1 else m.group(1))
    # CEPs
    ceps = re.findall(r"\d{5}-\d{3}|\d{8}", texto)
    cep_orig = ceps[0] if len(ceps)>0 else ""
    cep_dest = ceps[1] if len(ceps)>1 else ""
    # nNF
    nNF = re.search(r"\bnNF\b[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    nNF = nNF.group(1) if nNF else ""
    # docnun
    docnun = re.search(r"docnun[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    docnun = docnun.group(1) if docnun else ""
    placas = localizar_placas(texto)
    return {"arquivo":"","chave_acesso":chave,"data":data,"valor":v,"peso":p,"cep_origem":cep_orig,"cep_destino":cep_dest,"nNF":nNF,"docnun":docnun,"placas":placas}

def extract_from_pdf_bytes(bts):
    texto = extrair_texto_pdf_bytes(bts)
    # Chave
    chave = re.search(r"\d{44}", texto)
    chave = limpar_chave(chave.group(0)) if chave else ""
    # Data
    data = re.search(r"\d{2}/\d{2}/\d{4}", texto)
    data = datetime.strptime(data.group(0), "%d/%m/%Y").date().isoformat() if data else ""
    # Valor
    v = re.search(r"R\$[^\d]*([\d\.,]+)", texto)
    v = formatar_valor_br(v.group(1)) if v else ""
    # Peso
    p = re.search(r"([\d\.,]+)\s?kg", texto, flags=re.IGNORECASE) or re.search(r"peso[^\d]*([\d\.,]+)", texto, flags=re.IGNORECASE)
    p = formatar_valor_br(p.group(1)) if p else ""
    # CEPs
    ceps = re.findall(r"\d{5}-\d{3}|\d{8}", texto)
    cep_orig = ceps[0] if len(ceps)>0 else ""
    cep_dest = ceps[1] if len(ceps)>1 else ""
    # nNF
    nNF = re.search(r"\bnNF\b[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    nNF = nNF.group(1) if nNF else ""
    # docnun
    docnun = re.search(r"docnun[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    docnun = docnun.group(1) if docnun else ""
    placas = localizar_placas(texto)
    return {"arquivo":"","chave_acesso":chave,"data":data,"valor":v,"peso":p,"cep_origem":cep_orig,"cep_destino":cep_dest,"nNF":nNF,"docnun":docnun,"placas":placas}

def processar_arquivos(files):
    """Processa múltiplos arquivos e retorna dataframe"""
    rows = []
    for nome, conteudo in files:
        ext = nome.lower().split('.')[-1]
        if ext=="xml":
            info = extract_from_xml_bytes(conteudo)
        elif ext=="pdf":
            info = extract_from_pdf_bytes(conteudo)
        else:
            try:
                txt = conteudo.decode("latin-1", errors="ignore")
                info = {"arquivo":nome,"chave_acesso":limpar_chave(re.search(r"\d{44}", txt).group(0)) if re.search(r"\d{44}", txt) else "", "data":"","valor":"","peso":"","cep_origem":"","cep_destino":"","nNF":"","docnun":"","placas":localizar_placas(txt)}
            except:
                info = {"arquivo":nome,"error":"Extensão não suportada"}
        info["arquivo"] = nome
        rows.append(info)
    df = pd.DataFrame(rows)
    expected = ["arquivo","chave_acesso","data","valor","peso","cep_origem","cep_destino","nNF","docnun","placas"]
    for c in expected:
        if c not in df.columns: df[c]=""
    return df[expected]

def salvar_no_banco_local(df, path=DB_PATH):
    if df is None or df.empty: return
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    for _, r in df.iterrows():
        try:
            cursor.execute("""
            INSERT INTO notas (arquivo, chave_acesso, data, valor, peso, cep_origem, cep_destino, nNF, docnun, placas)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,(r.get("arquivo",""),r.get("chave_acesso",""),r.get("data",""),r.get("valor",""),r.get("peso",""),
                r.get("cep_origem",""),r.get("cep_destino",""),r.get("nNF",""),r.get("docnun",""),r.get("placas","")))
        except sqlite3.IntegrityError:
            pass
    conn.commit()
    conn.close()

# ===========================
# Interface Streamlit
# ===========================
criar_banco_local()

st.title("📄 Extrator de NF-e — Seguro e Dinâmico")

# --- Login / cadastro ---
if "logado" not in st.session_state:
    st.session_state["logado"] = False

if not st.session_state["logado"]:
    st.subheader("🔑 Login")
    username = st.text_input("Usuário")
    senha = st.text_input("Senha", type="password")
    # Verificar botão login
    if st.button("Entrar"):
        # primeiro acesso: cadastrar
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM usuarios WHERE username=?", (username,))
        if cursor.fetchone() is None:
            cadastrar_usuario(username, senha)
            st.success("Usuário cadastrado e logado!")
            st.session_state["logado"]=True
        else:
            ok,msg = verificar_login(username, senha)
            if ok:
                st.success("Login bem-sucedido!")
                st.session_state["logado"]=True
            else:
                st.error(msg)
        conn.close()
    st.stop()

# --- Upload de arquivos ---
uploaded_files = st.file_uploader("Envie XML/PDF (múltiplos permitidos)", accept_multiple_files=True)
if uploaded_files:
    files_list = [(f.name, f.getvalue()) for f in uploaded_files]
    st.info(f"{len(files_list)} arquivo(s) enviados. Processando...")
    df_novo = processar_arquivos(files_list)
    st.subheader("📊 Novas notas extraídas")
    st.dataframe(df_novo)

    # carregar histórico local
    conn = sqlite3.connect(DB_PATH)
    try:
        df_antigo = pd.read_sql_query("SELECT * FROM notas", conn)
    except:
        df_antigo = pd.DataFrame(columns=df_novo.columns)
    conn.close()

    # juntar e deduplicar por chave_acesso
    if not df_antigo.empty:
        df_total = pd.concat([df_antigo[df_antigo.columns.intersection(df_novo.columns)], df_novo], ignore_index=True)
    else:
        df_total = df_novo.copy()
    if "chave_acesso" in df_total.columns and df_total["chave_acesso"].notna().any():
        df_total = df_total.drop_duplicates(subset=["chave_acesso"], keep="last")

    st.subheader("📈 Histórico consolidado")
    st.dataframe(df_total)

    # salvar local
    salvar_no_banco_local(df_novo)

    # botão export CSV
    csv = df_total.to_csv(index=False).encode("utf-8")
    st.download_button("⬇️ Exportar histórico CSV", csv, "notas_extradas.csv", "text/csv")