# app.py
import streamlit as st
import pandas as pd
import re
import io
import sqlite3
import xml.etree.ElementTree as ET
import pdfplumber
import json
from google.oauth2.service_account import Credentials
import gspread
from datetime import datetime

st.set_page_config(page_title="Extrator de NF", layout="wide")

# ------------------------------
# CONFIGURAÇÕES
# ------------------------------
# ID da planilha
SHEET_ID = "132mwn9QnOYOcitfCkr5yJngE7Anr1KRdu_tb0EPFmtI"

# nome da aba (sheet) dentro da planilha
SHEET_TAB_NAME = None  # None -> usa sheet1

# ------------------------------
# UTILITÁRIOS de extração/format
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
        # troca separadores para padrão BR: 1.234.567,89
        return s.replace(",", "X").replace(".", ",").replace("X", ".")
    except:
        return "" if pd.isna(valor) else str(valor)

def localizar_placas(texto):
    if not texto:
        return ""
    t = texto.upper()
    # padrão antigo ABC1234 e mercosul ABC1D23
    pat = r"[A-Z]{3}[0-9]{4}|[A-Z]{3}[0-9][A-Z][0-9]{2}"
    achados = re.findall(pat, t)
    # remove duplicados preservando ordem
    seen = set(); placas = []
    for p in achados:
        if p not in seen:
            seen.add(p); placas.append(p)
    return ", ".join(placas)

def extrair_texto_pdf_bytes(bts):
    text = ""
    try:
        with pdfplumber.open(io.BytesIO(bts)) as pdf:
            for p in pdf.pages:
                text += "\n" + (p.extract_text() or "")
    except Exception:
        try:
            text = bts.decode("latin-1", errors="ignore")
        except:
            text = ""
    return text

# Extração de XML e PDF

def extract_from_xml_bytes(bts):
    try:
        root = ET.fromstring(bts)
    except Exception as e:
        return {"error": f"XML parse error: {e}"}

    texto = ET.tostring(root, encoding="utf-8", method="text").decode("utf-8")

    # tenta achar infNFe/@Id
    chave = ""
    try:
        # procurar por tag infNFe com atributo Id
        for elem in root.iter():
            tag = elem.tag
            if tag.lower().endswith("infnfe") and "Id" in elem.attrib:
                chave = limpar_chave(elem.attrib.get("Id", ""))
                if chave:
                    break
    except:
        chave = ""

    # se não achou pelo attr, procura 44 dígitos no texto
    if not chave:
        m = re.search(r"\d{44}", texto)
        if m:
            chave = limpar_chave(m.group(0))

    # data
    data = ""
    m = re.search(r"\d{4}-\d{2}-\d{2}", texto)
    if m:
        data = m.group(0)
    else:
        m2 = re.search(r"\d{2}/\d{2}/\d{4}", texto)
        if m2:
            # converte para ISO
            d = m2.group(0)
            try:
                data = datetime.strptime(d, "%d/%m/%Y").date().isoformat()
            except:
                data = d

    # valor vNF
    v = ""
    m = re.search(r"vNF[^0-9]*([\d\.,]+)", texto, flags=re.IGNORECASE)
    if m:
        v = formatar_valor_br(m.group(1))
    else:
        # busca R$ ...
        m2 = re.search(r"R\$[^\d]*([\d\.,]+)", texto)
        if m2:
            v = formatar_valor_br(m2.group(1))

    # peso
    p = ""
    m = re.search(r"(peso[^\d]*)([\d\.,]+)", texto, flags=re.IGNORECASE)
    if m:
        p = formatar_valor_br(m.group(2))
    else:
        m2 = re.search(r"([\d\.,]+)\s?kg", texto, flags=re.IGNORECASE)
        if m2:
            p = formatar_valor_br(m2.group(1))

    # CEPs
    cep_orig = ""
    cep_dest = ""
    ceps = re.findall(r"\d{5}-\d{3}|\d{8}", texto)
    if len(ceps) >= 1:
        cep_orig = ceps[0]
    if len(ceps) >= 2:
        cep_dest = ceps[1]

    # nNF (numero da nota)
    nNF = ""
    m = re.search(r"\bnNF\b[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        nNF = m.group(1)

    # docnun heuristica
    docnun = ""
    m = re.search(r"docnun[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        docnun = m.group(1)

    placas = localizar_placas(texto)

    return {
        "arquivo": "",
        "chave_acesso": chave,
        "data": data,
        "valor": v,
        "peso": p,
        "cep_origem": cep_orig,
        "cep_destino": cep_dest,
        "nNF": nNF,
        "docnun": docnun,
        "placas": placas
    }

def extract_from_pdf_bytes(bts):
    texto = extrair_texto_pdf_bytes(bts)

    # chave
    chave = ""
    m = re.search(r"\d{44}", texto)
    if m:
        chave = limpar_chave(m.group(0))

    # data
    data = ""
    m = re.search(r"\d{2}/\d{2}/\d{4}", texto)
    if m:
        try:
            data = datetime.strptime(m.group(0), "%d/%m/%Y").date().isoformat()
        except:
            data = m.group(0)

    # valor
    v = ""
    m = re.search(r"R\$[^\d]*([\d\.,]+)", texto)
    if m:
        v = formatar_valor_br(m.group(1))

    # peso
    p = ""
    m = re.search(r"([\d\.,]+)\s?kg", texto, flags=re.IGNORECASE)
    if m:
        p = formatar_valor_br(m.group(1))
    else:
        m2 = re.search(r"peso[^\d]*([\d\.,]+)", texto, flags=re.IGNORECASE)
        if m2:
            p = formatar_valor_br(m2.group(1))

    ceps = re.findall(r"\d{5}-\d{3}|\d{8}", texto)
    cep_orig = ceps[0] if len(ceps) > 0 else ""
    cep_dest = ceps[1] if len(ceps) > 1 else ""

    nNF = ""
    m = re.search(r"\bnNF\b[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        nNF = m.group(1)

    docnun = ""
    m = re.search(r"docnun[^0-9]*([0-9]+)", texto, flags=re.IGNORECASE)
    if m:
        docnun = m.group(1)

    placas = localizar_placas(texto)

    return {
        "arquivo": "",
        "chave_acesso": chave,
        "data": data,
        "valor": v,
        "peso": p,
        "cep_origem": cep_orig,
        "cep_destino": cep_dest,
        "nNF": nNF,
        "docnun": docnun,
        "placas": placas
    }

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
            # tenta decodificar texto (txt)
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
                    "nNF": "",
                    "docnun": "",
                    "placas": localizar_placas(txt)
                }
            except:
                info = {"arquivo": nome, "error": "extensão não suportada"}
        info["arquivo"] = nome
        rows.append(info)
    df = pd.DataFrame(rows)
    # garantir colunas esperadas
    expected = ["arquivo","chave_acesso","data","valor","peso","cep_origem","cep_destino","nNF","docnun","placas"]
    for c in expected:
        if c not in df.columns:
            df[c] = ""
    return df[expected]

# ------------------------------
# SQLite (backup local)
# ------------------------------
def criar_banco_local(path="nfe_local.db"):
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
        nNF TEXT,
        docnun TEXT,
        placas TEXT,
        criado_em TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
    """)
    conn.commit()
    conn.close()

def salvar_no_banco_local(df, path="nfe_local.db"):
    if df is None or df.empty:
        return
    conn = sqlite3.connect(path)
    cursor = conn.cursor()
    for _, r in df.iterrows():
        try:
            cursor.execute("""
            INSERT INTO notas (arquivo, chave_acesso, data, valor, peso, cep_origem, cep_destino, nNF, docnun, placas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r.get("arquivo",""),
                r.get("chave_acesso",""),
                r.get("data",""),
                r.get("valor",""),
                r.get("peso",""),
                r.get("cep_origem",""),
                r.get("cep_destino",""),
                r.get("nNF",""),
                r.get("docnun",""),
                r.get("placas","")
            ))
        except sqlite3.IntegrityError:
            # já existe (chave única)
            pass
    conn.commit()
    conn.close()

# ------------------------------
# Google Sheets (Service Account)
# ------------------------------
@st.cache_resource
def conectar_sheets():
    sa_json = st.secrets.get("GSPREAD_SERVICE_ACCOUNT")
    if not sa_json:
        return None, "Service account JSON não encontrado em Streamlit Secrets (GSPREAD_SERVICE_ACCOUNT)."
    try:
        if isinstance(sa_json, str):
            sa_info = json.loads(sa_json)
        else:
            sa_info = sa_json
        scopes = ["https://www.googleapis.com/auth/spreadsheets", "https://www.googleapis.com/auth/drive"]
        creds = Credentials.from_service_account_info(sa_info, scopes=scopes)
        client = gspread.authorize(creds)
        # abre a planilha
        sh = client.open_by_key(SHEET_ID)
        ws = sh.sheet1 if SHEET_TAB_NAME is None else sh.worksheet(SHEET_TAB_NAME)
        return ws, None
    except Exception as e:
        return None, f"Erro ao conectar Sheets: {e}"

def exportar_para_sheets(df, ws):
    if ws is None:
        raise ValueError("Worksheet (ws) está vazio")
    # limpar e atualizar
    ws.clear()
    # header + valores (convertendo NaN p/ "")
    df2 = df.fillna("").astype(str)
    ws.update([df2.columns.values.tolist()] + df2.values.tolist())

# ------------------------------
# INTERFACE STREAMLIT
# ------------------------------
st.title("📄 Extrator de NF-e — Upload e Envio Automático para Google Sheets")

st.markdown("""
Envie arquivos XML ou PDF. O sistema:
- extrai chave (44 dígitos), data, valor, peso, CEP origem/destino, nNF, docnun e placa(s);
- agrupa com o histórico (mantendo apenas a última por chave) e
- envia automaticamente para a planilha Google configurada.
""")

# criar banco local (backup)
criar_banco_local()

# uploader
uploaded_files = st.file_uploader("Envie XML/PDF (múltiplos permitidos)", accept_multiple_files=True)

# conectar ao sheets (se lives)
ws, err = conectar_sheets()
if err:
    st.warning(err)

if uploaded_files:
    # transformar em lista de tuplas (nome, bytes)
    files_list = [(f.name, f.getvalue()) for f in uploaded_files]

    st.info(f"{len(files_list)} arquivo(s) enviados. Processando...")
    df_novo = processar_arquivos(files_list)
    st.subheader("Novas notas extraídas")
    st.dataframe(df_novo)

    # carregar histórico local
    conn = sqlite3.connect("nfe_local.db")
    try:
        df_antigo = pd.read_sql_query("SELECT * FROM notas", conn)
    except:
        df_antigo = pd.DataFrame(columns=df_novo.columns)
    conn.close()

    # juntar e deduplicar por chave_acesso (manter o último)
    if not df_antigo.empty:
        df_total = pd.concat([df_antigo[df_antigo.columns.intersection(df_novo.columns)], df_novo], ignore_index=True)
    else:
        df_total = df_novo.copy()
    if "chave_acesso" in df_total.columns and df_total["chave_acesso"].notna().any():
        # manter último registro por chave (últimos adicionados aparecem por último)
        df_total = df_total.drop_duplicates(subset=["chave_acesso"], keep="last")
    # mostrar resultado
    st.subheader("Histórico consolidado (pré- Sheets)")
    st.dataframe(df_total)

    # salvar local (backup)
    salvar_no_banco_local(df_novo)

    # tentar exportar para Sheets automaticamente
    if ws is not None:
        try:
            exportar_para_sheets(df_total, ws)
            st.success("Dados exportados automaticamente para o Google Sheets!")
        except Exception as e:
            st.error(f"Erro ao exportar p/ Sheets: {e}")
            st.info("Você pode tentar exportar manualmente usando o botão abaixo.")
    else:
        st.info("Sem conexão com Sheets — verifique as Secrets e compartilha a planilha com a service account.")

    # botão para exportar manualmente
    if st.button("Exportar para Google Sheets (manual)"):
        if ws is None:
            st.error("Conexão com Sheets não configurada.")
        else:
            try:
                exportar_para_sheets(df_total, ws)
                st.success("Exportado com sucesso!")
            except Exception as e:
                st.error(f"Erro: {e}")

# Mostrar histórico salvo localmente
st.markdown("---")
st.subheader("Banco local (backup) — últimas 200 linhas")
conn = sqlite3.connect("nfe_local.db")
try:
    df_local = pd.read_sql_query("SELECT * FROM notas ORDER BY criado_em DESC LIMIT 200", conn)
    st.dataframe(df_local)
except Exception as e:
    st.write("Sem histórico local.")
conn.close()

st.info("Observação: para o envio automático para Google Sheets, configure a Service Account no Streamlit Secrets (key = GSPREAD_SERVICE_ACCOUNT).")

