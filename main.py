from src import pages
from streamlit_option_menu import option_menu

import streamlit as st


if "selected_page" not in st.session_state:
    st.session_state.selected_page = "Main"
    

st.set_page_config(
    page_title="My project",
    page_icon="💻"   
)

with st.sidebar:
    selected = option_menu("Yugo", ["Main","Malware Cre[HACK]tion I","PuzzleSQL"],menu_icon="bi-bookmark-check-fill", default_index=["Main","Malware Cre[HACK]tion I","PuzzleSQL"].index(st.session_state.selected_page))
    selected

    st.session_state.selected_page = selected

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

elif selected == "Malware Cre[HACK]tion I":
    pages.page_2()

elif selected == "PuzzleSQL":
    pages.page_3()
