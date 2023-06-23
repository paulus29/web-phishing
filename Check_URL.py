import streamlit as st 
from feature_extractor import *
import joblib
import pandas as pd
import whois
import pycountry

st.set_page_config(page_title="Phishing Detector")

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

@st.cache_resource(show_spinner=False)
def load_model():
  return joblib.load('model/voting1.joblib')

st.title("Phishing Website Detector")
with st.container():
  link = st.text_input("Enter the URL you want to check", placeholder='Enter the URL you want to check. Example: http://google.com', label_visibility='hidden')
  link = link.strip()
  if st.button('Check URL', use_container_width=True):
    if link:
      with st.spinner('Loading Model...'):
        model = load_model()
      try:
        with st.spinner("Please Wait. Extracting features..."):
          hasil = extract_features(link)
        if hasil:
          hasil = pd.DataFrame([hasil], columns=nama_column)
          
          with st.spinner('Please Wait. Predicting...'):
            if model.predict(hasil)[0] == 1:
              st.success("The URL you entered is **safe**")
            else:
              st.error("**ALERT**:grey_exclamation:  The URL you entered is probably **phishing**")
              
          _, domain, suffix = extract(link)
          whois_response = whois.whois(f'{domain}.{suffix}')
          
          tab1, tab2 = st.tabs(["Domain Info", "Extracted Features"])
          with tab1:
            if whois_response.domain_name:
              st.text(f'Domain Name            : {whois_response.domain_name}')
            else:
              st.text(f'Domain Name            : None')
            
            if whois_response.registrar:
              st.text(f'Domain Registrar       : {whois_response.registrar}')
            else:
              st.text(f'Domain Registrar       : None')
              
            if whois_response.creation_date:
              st.text(f'Domain Creation Date   : {(whois_response.creation_date if not isinstance(whois_response.creation_date, list) else whois_response.creation_date[0]).strftime("%A, %d %B %Y")}')
            else:
              st.text(f'Domain Creation Date   : None')
            
            if whois_response.expiration_date:
              st.text(f'Domain Expiration Date : {(whois_response.expiration_date if not isinstance(whois_response.expiration_date, list) else whois_response.expiration_date[0]).strftime("%A, %d %B %Y")}')
            else:
              st.text(f'Domain Expiration Date : None')
            
            if whois_response.org:
              st.text(f'Organization           : {whois_response.org}')
            else:
              st.text(f'Organization           : None')
              
            if whois_response.address:
              st.text(f'Address                : {whois_response.address}')
            else:
              st.text(f'Address                : None')
            
            if whois_response.city:
              st.text(f'City                   : {whois_response.city}')
            else:
              st.text(f'City                   : None')
            
            if whois_response.country:
              country = pycountry.countries.get(alpha_2=str(whois_response.country))
              if country:
                st.text(f'Country                : {country.name}')
              else:
                st.text(f'Country                : None')
            else:
              st.text(f'Country                : None')
          
          with tab2:
            df = hasil.T
            df = df.iloc[[24, 13, 25, 22, 14, 20, 6, 17, 23, 18, 2, 15, 4, 5, 11,
                          12, 19, 10, 21, 16, 7, 8, 9, 3, 1]]
            df.columns = ["Extracted Features"]
            st.write('Below are the features that our system has extracted from the URL you entered. The features below are ranked by importance according to our machine learning model from very important to less important.')
            st.dataframe(df, use_container_width=True)
        else:
          st.warning("Sorry, our system failed to get information from the URL you entered. Please go to the help menu to get further explanation")
      except:
        st.warning("Opps, it looks like the app has encountered an error")
    else:
      st.warning("Please enter the URL")
      