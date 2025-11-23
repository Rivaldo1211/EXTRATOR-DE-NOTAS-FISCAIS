import streamlit as st
import pandas as pd
import sqlite3
from main import processar_arquivos, salvar_no_banco
from google_sheets import exportar_google

st.title("📄 Sistema de Importação de NF-e")

uploaded = st.file_uploader("Envie arquivos .txt ou .xml", accept_multiple_files=True)

if uploaded:
    files_list = [(file.name, file.read()) for file in uploaded]
    df = processar_arquivos(files_list)

    st.write("Pré-visualização:")
    st.dataframe(df)

    if st.button("Salvar no Banco"):
        salvar_no_banco(df)
        st.success("Notas salvas com sucesso!")

conn = sqlite3.connect("nfe.db")
historico = pd.read_sql_query("SELECT * FROM notas", conn)
conn.close()

st.subheader("📊 Histórico de Notas")
st.dataframe(historico)

if st.button("Exportar para Google Sheets"):
    exportar_google(historico)
    st.success("Exportado com sucesso para o Sheets!")
