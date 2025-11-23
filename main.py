import pandas as pd
import re
import xml.etree.ElementTree as ET
import sqlite3
import io

# ----------------------------------------------------
# 🔍 Função para extrair a chave de acesso corretamente
# ----------------------------------------------------
def extrair_chave(texto):
    if texto is None:
        return ""

    numeros = re.findall(r'\d', texto)
    chave = "".join(numeros)

    if len(chave) == 44:
        return chave
    return ""

# ----------------------------------------------------
# 🔍 Função para extrair placas (aceita múltiplas)
# ----------------------------------------------------
def extrair_placas(texto):
    if texto is None:
        return ""

    placas = re.findall(r"[A-Z]{3}-?\d{4}", texto.upper())
    placas = list(set(placas))

    return ", ".join(placas) if placas else ""

# ----------------------------------------------------
# 🔍 Função para formatar peso e valor
# ----------------------------------------------------
def formatar_numero(valor):
    if pd.isna(valor):
        return ""
    try:
        valor = float(valor)
        return f"{valor:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except:
        return valor

# ----------------------------------------------------
# 🔍 Processar arquivos enviados (XML ou PDF extraído)
# ----------------------------------------------------
def processar_arquivos(files_list):
    dados = []

    for nome_arquivo, conteudo in files_list:

        if nome_arquivo.endswith(".xml"):
            tree = ET.parse(io.BytesIO(conteudo))
            root = tree.getroot()

            # Namespace
            ns = {"nfe": "http://www.portalfiscal.inf.br/nfe"}

            chave = extrair_chave(root.attrib.get("Id", ""))

            # Dados principais
            data = root.find(".//nfe:dhEmi", ns)
            peso = root.find(".//nfe:pesoB", ns)
            valor = root.find(".//nfe:vNF", ns)
            nNF = root.find(".//nfe:nNF", ns)

            # CEPs
            cep_orig = root.find(".//nfe:emit/nfe:enderEmit/nfe:CEP", ns)
            cep_dest = root.find(".//nfe:dest/nfe:enderDest/nfe:CEP", ns)

            # Informações complementares (placas podem estar aqui)
            infCpl = root.find(".//nfe:infCpl", ns)

            texto_completo = (
                (infCpl.text or "") +
                (root.findtext(".//nfe:transp", default="", namespaces=ns))
            )

            placas = extrair_placas(texto_completo)

            dados.append({
                "arquivo": nome_arquivo,
                "chave_acesso": chave,
                "data": data.text[:10] if data is not None else "",
                "valor": formatar_numero(valor.text if valor is not None else ""),
                "peso": formatar_numero(peso.text if peso is not None else ""),
                "cep_origem": cep_orig.text if cep_orig is not None else "",
                "cep_destino": cep_dest.text if cep_dest is not None else "",
                "nNF": nNF.text if nNF is not None else "",
                "docnun": chave[25:34] if chave else "",
                "placas": placas
            })

    return pd.DataFrame(dados)

# ----------------------------------------------------
# 🔌 Banco de dados SQLite
# ----------------------------------------------------
def conectar_banco():
    conn = sqlite3.connect("notas.db")
    return conn

def criar_tabela():
    conn = conectar_banco()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        arquivo TEXT,
        chave_acesso TEXT,
        data TEXT,
        valor TEXT,
        peso TEXT,
        cep_origem TEXT,
        cep_destino TEXT,
        nNF TEXT,
        docnun TEXT,
        placas TEXT
    )
    """)
    conn.commit()
    conn.close()

def salvar_no_banco(df):
    conn = conectar_banco()
    cursor = conn.cursor()

    for _, row in df.iterrows():
        cursor.execute("""
        INSERT INTO notas
        (arquivo, chave_acesso, data, valor, peso, cep_origem, cep_destino, nNF, docnun, placas)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            row["arquivo"], row["chave_acesso"], row["data"], row["valor"], row["peso"],
            row["cep_origem"], row["cep_destino"], row["nNF"], row["docnun"], row["placas"]
        ))

    conn.commit()
    conn.close()

def carregar_dados():
    conn = conectar_banco()
    df = pd.read_sql_query("SELECT * FROM notas", conn)
    conn.close()
    return df
