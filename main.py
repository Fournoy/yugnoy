from src import pages
from streamlit_option_menu import option_menu

import streamlit as st


st.set_page_config(
    page_title="Yugo",
    page_icon="💻"   
)

with st.sidebar:
    selected = option_menu("Yugo", ["Main","PuzzleSQL","Malware Cre[HACK]tion I"],menu_icon="bi-bookmark-check-fill", default_index=1)
    selected
st.markdown(
    """
    <style>
    .stApp {
        background-color: #000000;
        color: white;
    }

    [data-testid="stSidebar"] {
        background-color: #5D001E; /* Bordeaux */
    }

    [data-testid="stSidebar"] * {
        color: white;
    }
    </style>
    """,
    unsafe_allow_html=True
)



if selected == "Main":
    pages.page_1()

elif selected == "PuzzleSQL":
    pages.page_2()

elif selected == "Malware Cre[HACK]tion I":
    pages.page_3()
