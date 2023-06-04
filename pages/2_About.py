import streamlit as st 

st.set_page_config(page_title="About")

hide_menu_style = """
        <style>
        #MainMenu {visibility: hidden;}
        #phishing-website-detector > div > span {
          text-align: center;
        }
        #root > div:nth-child(1) > div.withScreencast > div > div > div > section > footer {
          visibility: hidden;
        }
        #root > div:nth-child(1) > div.withScreencast > div > div > header > div.css-14xtw13.e8zbici0 {
          visibility: hidden;
        }
        #phishing-website-detector > div > span {
          font-size: 4rem;
        }
        #root > div:nth-child(1) > div.withScreencast > div > div > header {
          visibility: hidden;
        }
        </style>
        """
st.markdown(hide_menu_style, unsafe_allow_html=True)


st.header("About the Application")
st.write("This app is powered by **machine learning** to detect whether a URL is :green[**safe**] or :red[**phishing**]. Our model is trained from thousands of :red[**phishing**] and :green[**non-phishing**] data available on the internet and offers reliable performance with an accuracy rate of around 97% on our test data.")
st.header("About the creator of this project")
st.write("This project was created by **Paulus Ricky Kurnianda**, a student from **Bina Nusantara University** majoring in computer science and mathematics. ")