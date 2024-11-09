import pickle
from flask import Flask, render_template, request
from urllib.parse import urlparse
import socket

app = Flask(__name__)

# Load the trained model
with open('phishing_detection_model.pkl', 'rb') as file:
    model = pickle.load(file)

# Feature extraction functions
def is_ip(url):
    try:
        socket.inet_aton(urlparse(url).hostname)
        return 1  # If the URL hostname is an IP address
    except:
        return -1

def is_long_url(url):
    return 1 if len(url) > 75 else -1

def is_short_url(url):
    return 1 if len(url) < 54 else -1

def has_symbol_at(url):
    return 1 if '@' in url else -1

def has_redirect(url):
    return 1 if '//' in urlparse(url).path else -1

def has_prefix_suffix(url):
    hostname = urlparse(url).hostname
    return 1 if '-' in hostname else -1

def count_subdomains(url):
    hostname = urlparse(url).hostname
    if hostname:
        return 1 if hostname.count('.') > 1 else -1
    return -1

def is_https(url):
    return 1 if urlparse(url).scheme == 'https' else -1

def has_non_std_port(url):
    return 1 if urlparse(url).port and urlparse(url).port not in [80, 443] else -1

def is_abnormal_url(url):
    hostname = urlparse(url).hostname
    if hostname:
        if len(hostname) > 50 or hostname.isdigit():
            return 1
    return -1

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']

        # Extract only the 10 accurately identifiable features from the URL
        features = [
            is_ip(url),               # 'UsingIP'
            is_long_url(url),         # 'LongURL'
            is_short_url(url),        # 'ShortURL'
            has_symbol_at(url),       # 'Symbol@'
            has_redirect(url),        # 'Redirecting//'
            has_prefix_suffix(url),   # 'PrefixSuffix-'
            count_subdomains(url),    # 'SubDomains'
            is_https(url),            # 'HTTPS'
            has_non_std_port(url),    # 'NonStdPort'
            is_abnormal_url(url)      # 'AbnormalURL'
        ]
        
        # Predict using the model
        prediction = model.predict([features])[0]
        result = "Phishing" if prediction == -1 else "Safe"

        # Render the result in the template
        return render_template('index.html', url=url, result=result, features=dict(zip([
            'UsingIP', 'LongURL', 'ShortURL', 'Symbol@', 'Redirecting//', 'PrefixSuffix-', 'SubDomains', 'HTTPS', 
            'NonStdPort', 'AbnormalURL'
        ], features)))
    
    return render_template('index1.html')

if __name__ == '__main__':
    app.run(debug=True)
