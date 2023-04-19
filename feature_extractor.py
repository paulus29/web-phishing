import requests
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from tldextract import extract
import ssl
import socket
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import time
import requests
import favicon
import re
from urllib.parse import urlparse

API = '4o4800co08ock08ccw444okcggc8kok04w4sogks' # 1
# API = 'o88cswc0g0w084gw84cscog8so8ck8sckkck4g4o' # 2
# API = 'o44ww8kc840c0oogk008kw4skgkgokcc0woc8swo' # 3
# API = 'gs8sgc8gkcswoo4scss404w84w4wo8so0gg8ksko' # 4
# API = 'sg884ok0s4kgcosk00cggs48k0c4kw0ok0w4sg88' # 5
# API = 'w8ocwswwcc4sgwcggo4ggk08kgw0s80g4448gskk' # 6
# API = 'sgk4swg0w8ggko4gkgckw0k40808wo0gs8cs088k' # 7
# API = 'wgowgk4s4o8s08kg0go0ckgg8ss0cgcc4ws8444c' # 8
# API = '8ggo0480g88w4s44os4ggw4goc8wc44k80g4co04' # 9
# API = 'o0ow8wcg8w848o4wgwwcgcwscoskgkksoc4sk0ck' # 10

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)|'  # IPv4 in hexadecimal
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}|'
        '[0-9a-fA-F]{7}', url)  # Ipv6
    if match:
        return 1
    else:
        return 0
    
def count_dot(url):
    num_dots = url.count('.')
    return num_dots

def has_special_symbol(url):
    num_at = url.count('@')
    num_dash = url.count('-')
    return num_at + num_dash

def url_length(url):
    return len(url) 
    
def has_suspicious_word(url):
    suspicious_keywords = ["security", "login", "signin", "bank", "account", "update", "include", "webs", "online"]
    for keyword in suspicious_keywords:
        if keyword in url.lower():
            return 1
    return 0

def count_tld(url):
    # print('count_tld')
    parsed_url = urlparse(url)
    tld_list = ['co', 'com', 'org', 'net', 'gov', 'edu', 'mil', 'biz', 'info', 'name', 'pro', 'aero', 'coop', 'int', 'museum', 'jobs', 'mobi', 'travel', 'cat', 'asia', 'tel', 'post', 'xyz']
    
    # Get all parts of the URL, including the domain and path
    url_parts = parsed_url.netloc + parsed_url.path
    base_domain = parsed_url.netloc
    tld_count = 0
    for part in base_domain.split('.'):
        if part in tld_list:
            tld_count += 1
    if tld_count > 1:
        return 1

    tld_count = 0
    for path in url_parts.split('/'):
        for part in path.split('.'):
            # print(part)
            if part in tld_list:
                tld_count += 1
    if tld_count > 1:
        return 1
    return 0

def HTTPS_token(url):
    match=re.search('https://|http://',url)
    if (match.start(0)==0):
        url=url[match.end(0):]
    match=re.search('http|https',url)
    if match:
        return 1
    else:
        return 0
    
allbrand_txt = open("all_brands.txt", "r")

def __txt_to_list(txt_object):
    list1 = []
    for line in txt_object:
        list1.append(line.strip())
    txt_object.close()
    return list1

allbrand = __txt_to_list(allbrand_txt)
def incorrect_brand_position(url):
    parsed_url = urlparse(url)
    extracted = extract(url)
    
    for i in allbrand:
        if i in extracted.subdomain.lower() or i in parsed_url.path.lower():
            return 1
    return 0

def check_data_uri(soup):
    pattern = re.compile(r"data:(.*?)[;,]")
    if pattern.search(str(soup)):
        return 1
    else:
        return 0
    
def fake_login_form(url, soup):
    _, domain, _ = extract(url)
    forms = soup.findAll('form', action=True)
    for form in forms:
        action = form.get('action')
        _, form_domain, _ = extract(action)
        if not action or action == '#' or action.startswith('javascript:void(0)'):
            return 1
        elif action.endswith('.php'):
            return 1
        elif domain not in form_domain and form_domain != "":
            return 1
    return 0

def hyperlink_features(url, soup):
    # print('hyperlink_features')
    img_links = [img['src'] for img in soup.find_all('img', src=True)]
    script_links = [script['src'] for script in soup.find_all('script', src=True)]
    frame_links = [frame['src'] for frame in soup.find_all('frame', src=True)]
    input_links = [input['src'] for input in soup.find_all('input', src=True)]
    link_links = [link['href'] for link in soup.find_all('link', href=True)]
    anchor_links = [anchor['href'] for anchor in soup.find_all('a', href=True)]
    website_domain = urlparse(url).netloc
    all_links = set(img_links + script_links + frame_links + input_links + link_links + anchor_links)
    total_links = len(all_links)
    if total_links == 0:
        no_hyperlink = 1
    else:
        no_hyperlink = 0
    # print(all_links)
    empty_links = 0
    error_links = 0
    redirection_links = 0
    foreign_links = 0
    for i, link in enumerate(all_links):
        if link == '#' or link == '#content' or link.lower() == 'javascript::void(0)':
            empty_links += 1

        link_domain = urlparse(link).netloc
        if link_domain != '' and link_domain != website_domain:
            foreign_links += 1

        # try:
        #     response = requests.get(link, timeout=1)
        #     if response.status_code == 404 or response.status_code == 403:
        #         error_links += 1
        #     if response.status_code == 301 or response.status_code == 302:
        #         redirection_links += 1
        # except:
        #     # Ignore any exceptions while trying to access the link
        #     pass
    if total_links == 0:
        return total_links, no_hyperlink, 0.0, 0.0
    foreign_ratio = foreign_links / total_links
    empty_ratio = empty_links / total_links
    # error_ratio = error_links / total_links
    # redirection_ratio = redirection_links / total_links
    # foreign_ration_feature = 1 if foreign_ratio > 0.5 else 0
    # empty_ratio_feature = 1 if empty_ratio > 0.34 else 0
    # error_ratio_feature = 1 if error_ratio > 0.3 else 0
    # redirection_ratio_feature = 1 if redirection_ratio > 0.3 else 0
    # print('foreign_ration_feature', foreign_ratio)
    # print('empty_ratio_feature', empty_ratio)
    # print('error_ratio_feature', error_ratio)
    # print('redirection_ratio_feature', redirection_ratio)
    return total_links, no_hyperlink, foreign_ratio, empty_ratio

def check_external_css_foreign_domain(url, soup):
    # print('check_external_css_foreign_domain')
    css_links = soup.find_all('link', rel='stylesheet')
    _, domain, suffix = extract(url)
    domain = domain + "." + suffix
    for css_link in css_links:
        if css_link.has_attr('href'):
            href = css_link['href']
            if 'http' in href or 'https' in href:
                _, href_domain, suffix = extract(href)
                href_domain = href_domain + "." + suffix
                if domain != href_domain:
                    return 1
    return 0

def find_copyright(url, soup):
    # print('find_copyright')
    _, domain, _ = extract(url)
    copyright_text = soup.find_all(['p', 'span'])
    for element in copyright_text:
        if 'copyright' in element.get_text().lower() \
            or '©' in element.get_text().lower() \
            or 'all rights reserved' in element.get_text().lower() \
            or '&copy' in element.get_text().lower():
            if domain in element.get_text().lower():
                return 0
    return 1

from sklearn.feature_extraction.text import TfidfVectorizer

def identity_keywords(url, soup):
    # print('identity_keywords')
    try:
        meta = soup.find_all('meta')
        meta_keywords = [m.attrs.get("content") for m in meta if m.attrs.get("name") == "keywords"]
        vectorizer = TfidfVectorizer(stop_words='english')
        if soup.title != None:
            title = soup.title.string
            text = [title] + meta_keywords
        else:
            text = meta_keywords
        if len(text) == 0:
            return 1
        tfidf = vectorizer.fit_transform(text)
        top_keywords = [vectorizer.get_feature_names_out()[i] for i in tfidf[0].indices[:5]]
        identity_keywords = set(meta_keywords + top_keywords)
        _, domain, suffix = extract(url)
        if any(keyword in domain for keyword in identity_keywords):
            return 0
        else:
            return 1
    except:
        return 1
    
def check_favicon(url):
    # print('check_favicon')
    try:
        icons = favicon.get(url, timeout=5)
        _, base_domain, _ = extract(url)
        for icon in icons:
            subdomain, domain, suffix = extract(icon.url)
            fav_domain = domain
            if base_domain in fav_domain:
                return 0
        return 1
    except:
        return 1
    
def SSLfinal_State(page_response):
#     print('SSLfinal_State')
    list_of_trsuted_issuer = ['geotrust', 'godaddy', 'network', 'thawte', 'comodo',
                                'doster', 'verisign', 'rapidssl', 'sectigo', 'certum',
                                'google', 'amazon', 'facebook', 'globalsign','symantec']
    try:
        real_url = page_response.url
        # print(real_url)
        index = real_url.find("://")
        split_url = real_url[index+3:]
        index = split_url.find("/")
        hostname = split_url[:index]
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.connect((hostname, 443))
            cert = s.getpeercert()

        issuer = dict(x[0] for x in cert['issuer'])['organizationName']
        issuer = re.sub(r'[^\w\s]', ' ', issuer)
        issuer = issuer.lower()
        issuer = issuer.split(' ')[0]
        if re.match('https://',real_url) is not None and issuer in list_of_trsuted_issuer:
            return 1
        elif re.match('https://',real_url):
            return 0
        else:
            return -1
    except Exception as e:
        return -1

def domain_registration_length(whois_res):
    try:
        expiration_date = whois_res.expiration_date  if not isinstance(whois_res.expiration_date, list) else whois_res.expiration_date[0]
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        if expiration_date:
            if type(expiration_date) == list:
                expiration_date = min(expiration_date)
            return abs((expiration_date - today).days)
        else:
            return 0
    except:
        return 0
    
def age_of_domain(whois_res):
    try:
        creation_date = whois_res.creation_date if not isinstance(whois_res.creation_date, list) else whois_res.creation_date[0]
        today = time.strftime('%Y-%m-%d')
        today = datetime.strptime(today, '%Y-%m-%d')
        return abs((today - creation_date).days)
    except Exception as e:
        return 0
    
def get_pagerank(url):
    extract_res = extract(url)
    url_ref = extract_res.domain + "." + extract_res.suffix
    headers = {'API-OPR': API}
    domain = url_ref
    req_url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + domain
    request = requests.get(req_url, headers=headers)
    result = request.json()
    page_rank = result['response'][0]['page_rank_decimal']
    return page_rank

def extract_features(url):
    features = []
    if not url.startswith('http'):
        url = f"http://{url}"
    try:
        page = requests.get(url, timeout=5)
        status = True
    except:
        status = False
    
    if status:
        try:
            url = page.url
            soup = BeautifulSoup(page.content, 'html.parser', from_encoding='iso-8859-1')
            _, domain, suffix = extract(url)
            whois_response = whois.whois(f'{domain}.{suffix}')
            features.append(url)
            features.append(having_ip_address(url))
            features.append(count_dot(url))
            features.append(has_special_symbol(url))
            features.append(url_length(url))
            features.append(has_suspicious_word(url))
            features.append(count_tld(url))
            features.append(HTTPS_token(url))
            features.append(incorrect_brand_position(url))
            features.append(check_data_uri(soup))
            features.append(fake_login_form(url, soup))
            features.extend(hyperlink_features(url, soup))
            features.append(check_external_css_foreign_domain(url, soup))
            features.append(find_copyright(url, soup))
            features.append(identity_keywords(url, soup))
            features.append(check_favicon(url))
            features.append(SSLfinal_State(page))
            features.append(domain_registration_length(whois_response))
            features.append(age_of_domain(whois_response))
            features.append(get_pagerank(url))
            return features
        except Exception as e:
            return None
    return None

nama_column =[
    'url',
    'ip_address',
    'count_dot',
    'special_symbol',
    'length_of_url',
    'has_suspicious_word',
    'count_tld',
    'HTTPS_token',
    'incorrect_brand_position',
    'check_data_uri',
    'fake_login_form',
    'total_hyperlinks',
    'no_hyperlinks',
    'foreign_ratio_links',
    'empty_ratio_links',
    'external_css',
    'copyright',
    'identity_keywords',
    'favicon', 
    'SSLfinal_State',
    'domain_registration_length',
    'age_of_domain',
    'page_rank'
]