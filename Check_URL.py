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

st.title("Phishing Website Detector")
with st.container():
  link = st.text_input("Enter the URL you want to check", placeholder='Enter the URL you want to check. Example: http://google.com', label_visibility='hidden')
  link = link.strip()
  if st.button('Check URL', use_container_width=True):
    if link:
      with st.spinner('Loading Model...'):
        model = joblib.load('model/voting1.joblib')
      try:
        with st.spinner("Please Wait. Extracting features..."):
          hasil = extract_features(link)
        if hasil:
          hasil = pd.DataFrame([hasil], columns=nama_column)
          
          with st.spinner('Please Wait. Predicting...'):
            if model.predict(hasil)[0] == 1:
              st.success("The URL you entered is **safe**")
            else:
              st.error(":grey_exclamation:**ALERT**:grey_exclamation:  The URL you entered is probably **phishing**")
              
          _, domain, suffix = extract(link)
          whois_response = whois.whois(f'{domain}.{suffix}')
          tab1, tab2 = st.tabs(["Domain Info", "Features Extracted"])
          with tab1:
            st.text(f'Domain Name            : {whois_response.domain_name}')
            st.text(f'Domain Registrar       : {whois_response.registrar}')
            st.text(f'Domain Creation Date   : {(whois_response.creation_date if not isinstance(whois_response.creation_date, list) else whois_response.creation_date[0]).strftime("%A, %d %B %Y")}')
            st.text(f'Domain Expiration Date : {(whois_response.expiration_date if not isinstance(whois_response.expiration_date, list) else whois_response.expiration_date[0]).strftime("%A, %d %B %Y")}')
            st.text(f'Organization           : {whois_response.org}')
            st.text(f'Address                : {whois_response.address}')
            st.text(f'City                   : {whois_response.city}')
            country = pycountry.countries.get(alpha_2=str(whois_response.country))
            if country:
              st.text(f'Country                : {country.official_name}')
            else:
              st.text(f'Country                : None')
          
          with tab2:
            st.write(hasil)
        else:
          st.warning("Sorry, our system failed to get information from the URL you entered. Please go to the help menu to get further explanation")
      except:
        st.write("Opps, it looks like the app has encountered an error")
    else:
      st.write("Please enter the URL")
      