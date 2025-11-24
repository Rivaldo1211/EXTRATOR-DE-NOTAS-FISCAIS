import streamlit as st
import pandas as pd
import sqlite3
from io import BytesIO
from PyPDF2 import PdfReader
import xml.etree.ElementTree as ET

# ==============================
# BANCO DE DADOS
# ==============================
def criar_banco():
    conn = sqlite3.connect("notas.db")
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        arquivo TEXT,
        chave_acesso TEXT,
        data TEXT,
        valor REAL,
        peso REAL,
        cep_origem TEXT,
        cep_destino TEXT,
        nNF TEXT,
        docnum TEXT,
        placa TEXT
    )
    """)
    conn.commit()
    conn.close()

def salvar_no_banco(df):
    conn = sqlite3.connect("notas.db")
    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute("""
        INSERT INTO notas
        (arquivo, chave_acesso, data, valor, peso, cep_origem, cep_destino, nNF, docnum, placa)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["arquivo"],
            row["chave_acesso"],
            row["data"],
            row["valor"],
            row["peso"],
            row["cep_origem"],
            row["cep_destino"],
            row["nNF"],
            row["docnum"],
            row["placa"]
        ))

    conn.commit()
    conn.close()

def carregar_todas_notas():
    conn = sqlite3.connect("notas.db")
    df = pd.read_sql_query("SELECT * FROM notas", conn)
    conn.close()
    return df

# ==============================
# EXTRAÇÃO XML
# ==============================
def ler_xml(conteudo):
    try:
        root = ET.fromstring(conteudo)

        ns = {"ns": "http://www.portalfiscal.inf.br/nfe"}

        chave = root.find(".//ns:infNFe", ns).attrib.get("Id", "")[3:]
        data = root.find(".//ns:dhEmi", ns).text
        valor = root.find(".//ns:vNF", ns).text
        peso = root.find(".//ns:pesoB", ns).text if root.find(".//ns:pesoB", ns) is not None else "0"
        origem = root.find(".//ns:enderEmit/ns:CEP", ns).text
        destino = root.find(".//ns:enderDest/ns:CEP", ns).text
        nNF = root.find(".//ns:ide/ns:nNF", ns).text
        docnum = root.find(".//ns:ide/ns:cNF", ns).text
        placa = root.find(".//ns:veicTransp/ns:placa", ns).text

        return {
            "chave_acesso": chave,
            "data": data,
            "valor": float(valor.replace(",", ".")),
            "peso": float(peso.replace(",", ".")),
            "cep_origem": origem,
            "cep_destino": destino,
            "nNF": nNF,
            "docnum": docnum,
            "placa": placa
        }

    except:
        return None

# ==============================
# APP STREAMLIT
# ==============================
st.title("📄 Extrator de Notas Fiscais (XML / PDF)")
st.write("Versão simples — sem criptografia")

criar_banco()

uploaded_files = st.file_uploader("Envie arquivos XML ou PDFs", accept_multiple_files=True)

dados_extraidos = []

if uploaded_files:
    for file in uploaded_files:
        nome = file.name
        if nome.endswith(".xml"):
            conteudo = file.read()
            resultado = ler_xml(conteudo)

            if resultado:
                resultado["arquivo"] = nome
                dados_extraidos.append(resultado)

if dados_extraidos:
    df = pd.DataFrame(dados_extraidos)

    # Deixa cabeçalhos MAIÚSCULOS
    df.columns = [c.upper() for c in df.columns]

    st.dataframe(df)

    if st.button("Salvar no banco de dados"):
        salvar_no_banco(df.rename(columns=str.lower))
        st.success("Notas adicionadas ao banco!")

st.divider()
st.subheader("📚 Notas já salvas no banco")

df_bd = carregar_todas_notas()
df_bd.columns = [c.upper() for c in df_bd.columns]
st.dataframe(df_bd)
