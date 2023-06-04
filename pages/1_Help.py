import streamlit as st 

st.set_page_config(page_title="Help")

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

st.title('HELP')
st.header("how to use this app:question:")
st.write("This app is very easy to use. All you have to do is paste the URL you want to check into the app and click on the check URL button. The app will give you the results whether the URL is :green[**safe**] or :red[**phishing**].")
st.write("The output results are divided into 3 namely:")
st.success("The URL you entered is **safe**")
st.write("This means that the machine learning model implemented in this application detects that the URL you entered is :green[**safe**] for you to visit.")
st.error(":grey_exclamation:**ALERT**:grey_exclamation:  The URL you entered is probably **phishing**")
st.write("This means that the machine learning model implemented in this app has detected that the URL you entered is :red[**phishing**]. We recommend not visiting it as it is **dangerous** and can **steal your personal data** if you are not careful.")
st.warning("Sorry, our system failed to get information from the URL you entered. Please go to the help menu to get further explanation")
st.markdown("""This means that the system fails to obtain the information to extract the features needed by the machine learning model to make predictions. This can be caused by:
1. The server takes a **long time** to send the response. The time tolerance allowed by the application to receive a response from the server is 5 seconds.
2. The server gives a **404 error status** response which means the page was not found or another similar error status.
3. The application encountered an error that caused the program to crash while **extracting features**. We are working to prevent this from happening.""")
st.header("How does this app work:question:")
st.write("After you enter the URL you want to check whether it is :green[**safe**] or :red[**phishing**] and press the **check URL** button, the system will try to get information from the URL by sending a **request**. If the request is responded by the server of the website, the system will try to **get the information needed by the machine learning model** implemented in this application to predict whether the URL is :green[**safe**] or :red[**phishing**]. The information can be the **characteristics of the URL**, **the content of the website**, or **information about the domain used in the URL**.")