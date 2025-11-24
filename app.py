# app_streamlit_protected.py
# Streamlit app with simple password protection using Fernet encryption
# - Generates a Fernet key (secret.key) if it doesn't exist
# - Encrypts the provided access password and stores it in password.enc
# - Authentication screen asks for password and compares with decrypted stored password
# - Allows upload of CSV/XLSX/XML (NF-e) files
# - For NF-e XML files it attempts to extract: municipio_origem, municipio_destino, empresa_emissora
# - Adds columns municipio_origem, municipio_destino, empresa_emissora when missing

import os
import io
import base64
import pandas as pd
import streamlit as st
from cryptography.fernet import Fernet
import xml.etree.ElementTree as ET
from typing import Optional, Dict, List

# ---------- Configuration (change paths if needed) ----------
KEY_FILE = "secret.key"          # file that stores the Fernet key (keep secret, do not commit)
PASS_FILE = "password.enc"      # file that stores the encrypted password
# default password requested by user (will be encrypted and saved when first run)
DEFAULT_PASSWORD = "Codigo20767@"

# ---------- Helpers for encryption ----------

def generate_and_save_key(path: str = KEY_FILE) -> bytes:
    key = Fernet.generate_key()
    with open(path, "wb") as f:
        f.write(key)
    return key


def load_key(path: str = KEY_FILE) -> bytes:
    if not os.path.exists(path):
        return generate_and_save_key(path)
    with open(path, "rb") as f:
        return f.read()


def encrypt_password(password: str, key: bytes, path: str = PASS_FILE) -> bytes:
    f = Fernet(key)
    token = f.encrypt(password.encode())
    with open(path, "wb") as f_out:
        f_out.write(token)
    return token


def decrypt_password(token: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(token).decode()


def load_encrypted_password(path: str = PASS_FILE) -> Optional[bytes]:
    if not os.path.exists(path):
        return None
    with open(path, "rb") as f:
        return f.read()

# ---------- Helpers to parse NF-e XMLs (expanded with more fields) (robust to namespaces) ----------

def strip_ns(tag: str) -> str:
    # removes namespace from an XML tag
    if '}' in tag:
        return tag.split('}', 1)[1]
    return tag


def find_text_by_path(root: ET.Element, path: List[str]) -> Optional[str]:
    # tries to descend by tag names ignoring namespaces
    # path is a list like ['infNFe','dest','enderDest','xMun']
    nodes = [root]
    for p in path:
        next_nodes = []
        for node in nodes:
            for child in node:
                if strip_ns(child.tag) == p:
                    next_nodes.append(child)
        if not next_nodes:
            return None
        nodes = next_nodes
    # return text of first matching node
    if nodes:
        return nodes[0].text.strip() if nodes[0].text else None
    return None


def parse_nfe_xml_bytes(file_bytes: bytes) -> Dict[str, Optional[str]]:
    # Parse XML and extract municipality origin/dest and issuer company
    try:
        tree = ET.fromstring(file_bytes)
    except Exception:
        # Additional fields
    chave_acesso = find_text_by_path(infNFe, ['ide','cNF']) or None
    valor_total = find_text_by_path(infNFe, ['total','ICMSTot','vNF']) or None
    cnpj_emitente = find_text_by_path(infNFe, ['emit','CNPJ']) or None

    return {"municipio_origem": None, "municipio_destino": None, "empresa_emissora": None}

    # find infNFe element (some XMLs wrap NFe/NFe or NFe/infNFe)
    # We'll search for element with tag name infNFe regardless of namespace
    infNFe = None
    for elem in tree.iter():
        if strip_ns(elem.tag) == 'infNFe':
            infNFe = elem
            break
    if infNFe is None:
        # maybe tree itself is infNFe
        if strip_ns(tree.tag) == 'infNFe':
            infNFe = tree
    if infNFe is None:
        # fallback to tree
        infNFe = tree

    municipio_dest = find_text_by_path(infNFe, ['dest','enderDest','xMun']) or find_text_by_path(infNFe, ['dest','enderDest','cMun'])
    municipio_orig = find_text_by_path(infNFe, ['emit','enderEmit','xMun']) or find_text_by_path(infNFe, ['dest','enderDest','xMun'])
    # issuer name usually in emit/xNome
    empresa = find_text_by_path(infNFe, ['emit','xNome']) or find_text_by_path(infNFe, ['emit','xFant'])

    return {
        "municipio_origem": municipio_orig,
        "municipio_destino": municipio_dest,
        "empresa_emissora": empresa,
    }

# ---------- Streamlit UI ----------

st.set_page_config(page_title="NF-e - Protegido", layout="wide")
st.title("Aplicativo NF-e — Acesso Protegido")

# Ensure key exists
key = load_key()

# Ensure encrypted password exists; if not create it from DEFAULT_PASSWORD
enc_pass = load_encrypted_password()
if enc_pass is None:
    enc_pass = encrypt_password(DEFAULT_PASSWORD, key)
    st.info("Arquivo de senha não encontrado: foi gerado e armazenado localmente.")

# Login
if 'autenticado' not in st.session_state:
    st.session_state['autenticado'] = False

if not st.session_state['autenticado']:
    # ensure new fields exist if missing
    for c in ['chave_acesso','valor_total','cnpj_emitente']:
        if c not in df_merged.columns:
            df_merged[c] = None

    st.subheader("Login")
    pwd = st.text_input("Senha de acesso", type="password")
    if st.button("Entrar"):
        try:
            stored = load_encrypted_password()
            if stored is None:
                st.error("Senha armazenada não encontrada — rode novamente para regenerar.")
            else:
                real = decrypt_password(stored, key)
                if pwd == real:
                    st.session_state['autenticado'] = True
                    st.success("Autenticado com sucesso!")
                else:
                    st.error("Senha incorreta.")
        except Exception as e:
            st.error(f"Erro ao verificar senha: {e}")
    st.stop()

# If authenticated, show main app
st.sidebar.success("Usuário autenticado")

st.header("Upload e processamento de arquivos")
st.write("Faça upload de arquivos CSV, XLSX ou arquivos NF-e em XML. O app tentará extrair município origem/destino e empresa emissora.")

uploaded_files = st.file_uploader("Carregar arquivos (pode selecionar múltiplos)", accept_multiple_files=True, type=['csv','xlsx','xls','xml'])

all_dfs = []
xml_records = []

if uploaded_files:
    for uploaded in uploaded_files:
        name = uploaded.name
        try:
            data = uploaded.read()
            if name.lower().endswith('.xml'):
                rec = parse_nfe_xml_bytes(data)
                # create a one-row dataframe with extracted fields
                df_xml = pd.DataFrame([rec])
                df_xml['source_file'] = name
                xml_records.append(df_xml)
            elif name.lower().endswith('.csv'):
                df = pd.read_csv(io.BytesIO(data))
                df['source_file'] = name
                all_dfs.append(df)
            elif name.lower().endswith(('.xls','xlsx')):
                df = pd.read_excel(io.BytesIO(data))
                df['source_file'] = name
                all_dfs.append(df)
            else:
                st.warning(f"Formato não suportado: {name}")
        except Exception as e:
            st.error(f"Erro ao processar {name}: {e}")

    # concat all tabular files and xml-derived records
    if all_dfs:
        df_total = pd.concat(all_dfs, ignore_index=True)
    else:
        df_total = pd.DataFrame()

    if xml_records:
        df_xml_all = pd.concat(xml_records, ignore_index=True)
    else:
        df_xml_all = pd.DataFrame()

    # merge xml info to tabular data when possible by source_file
    if not df_total.empty and not df_xml_all.empty:
        # try join on source_file if present
        if 'source_file' in df_total.columns and 'source_file' in df_xml_all.columns:
            df_merged = df_total.merge(df_xml_all, on='source_file', how='left')
        else:
            df_merged = df_total.copy()
            # append columns from xml
            for c in ['municipio_origem','municipio_destino','empresa_emissora']:
                if c not in df_merged.columns:
                    df_merged[c] = None
    elif not df_total.empty:
        df_merged = df_total.copy()
    elif not df_xml_all.empty:
        # only xmls
        df_merged = df_xml_all.copy()
    else:
        df_merged = pd.DataFrame()

    # Ensure the three columns exist
    for c in ['municipio_origem','municipio_destino','empresa_emissora']:
        if c not in df_merged.columns:
            df_merged[c] = None

    st.subheader("Preview dos dados processados")
    st.dataframe(df_merged.head(200))

    # Give user the option to download processed CSV
    if not df_merged.empty:
        csv = df_merged.to_csv(index=False).encode('utf-8')
        b64 = base64.b64encode(csv).decode()
        href = f"data:file/csv;base64,{b64}"
        st.markdown(f"[Baixar CSV processado]({href})")

    # Save processed file locally if user wants
    if st.button("Salvar arquivo processado em 'processed_output.csv'"):
        try:
            df_merged.to_csv('processed_output.csv', index=False)
            st.success("Salvo como processed_output.csv")
        except Exception as e:
            st.error(f"Erro ao salvar arquivo: {e}")

# ---------- Administração: regenerar chave / senha (opcional) ----------
st.sidebar.header("Admin")
if st.sidebar.button("Regenerar chave Fernet (gera nova secret.key)"):
    key = generate_and_save_key()
    st.sidebar.success("Nova chave gerada. ATENÇÃO: senhas já criptografadas com a chave antiga NÃO serão mais descriptografáveis.")

if st.sidebar.button("Atualizar senha armazenada para Codigo20767@"):
    try:
        encrypt_password(DEFAULT_PASSWORD, key)
        st.sidebar.success("Senha atualizada e armazenada criptografada.")
    except Exception as e:
        st.sidebar.error(f"Erro ao armazenar senha: {e}")

st.sidebar.markdown("**Segurança:** não comite 'secret.key' ou 'password.enc' no repositório. Use variáveis de ambiente ou serviços de segredo para produção.")

# End of file
