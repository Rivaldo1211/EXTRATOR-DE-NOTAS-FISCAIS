import streamlit as st
from utils.pdf_extractor import extract_text_from_pdf
from utils.xml_extractor import extract_data_from_xml
from utils.helpers import save_uploaded_file

st.set_page_config(page_title="Extrator de Notas Fiscais", layout="wide")

st.title("📄 Extrator de Notas Fiscais (PDF/XML)")

menu = st.sidebar.radio("Selecione o tipo de arquivo:", ["PDF", "XML"])

uploaded_file = st.file_uploader("Envie o arquivo", type=["pdf", "xml"])

if uploaded_file:
    file_path = save_uploaded_file(uploaded_file)

    if menu == "PDF":
        st.subheader("📑 Texto extraído do PDF:")
        text = extract_text_from_pdf(file_path)
        st.text_area("Resultado", text, height=400)

    elif menu == "XML":
        st.subheader("📦 Dados extraídos do XML:")
        xml_data = extract_data_from_xml(file_path)
        st.json(xml_data)