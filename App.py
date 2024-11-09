import pickle
import pandas as pd
from flask import Flask, render_template, request,redirect, url_for
from urllib.parse import urlparse
import socket
from pymongo import MongoClient

app = Flask(__name__)

# MongoDB connection setup
mongo_client = MongoClient('mongodb+srv://l211763:mohsin123@cluster0.2wthpzf.mongodb.net/FYP?retryWrites=true&w=majority')
#mongo_client = MongoClient('mongodb+srv://l200987:HGHGpJJnR9neG8ca@cluster0.bfcos.mongodb.net/')
db = mongo_client['FYP']
user_collection = db['users']
history_collection = db['History']

# Load the trained model
with open('phishing_detection_model.pkl', 'rb') as file:
    model = pickle.load(file)

# Load the CSV file as a database
csv_file = 'url_database.csv'

# Function to load the CSV
def load_csv():
    try:
        return pd.read_csv(csv_file)
    except FileNotFoundError:
        return pd.DataFrame(columns=['url', 'label'])

# Function to save to the CSV
def save_to_csv(df):
    df.to_csv(csv_file, index=False)

# Feature extraction functions (same as before)
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
def dashboard():
    # Get the userId from the query parameters
    user_id = request.args.get('userId')
    email = None
    history_records = []

    # Retrieve the email from MongoDB using userId
    if user_id:
        user_data = user_collection.find_one({'userId': user_id})
        if user_data:
            email = user_data['email']
            # Retrieve history records for the user
            history_records = list(history_collection.find({'userId': user_id}))

    if request.method == 'POST':
        url = request.form['url']
        
        # Extract all features for the given URL
        features = {
            'UsingIP': is_ip(url),
            'LongURL': is_long_url(url),
            'ShortURL': is_short_url(url),
            'Symbol@': has_symbol_at(url),
            'Redirecting//': has_redirect(url),
            'PrefixSuffix-': has_prefix_suffix(url),
            'SubDomains': count_subdomains(url),
            'HTTPS': is_https(url),
            'NonStdPort': has_non_std_port(url),
            'AbnormalURL': is_abnormal_url(url)
        }
        
        # Load the CSV database
        df = load_csv()

        # Check if the URL is already in the database
        if url in df['url'].values:
            label = df.loc[df['url'] == url, 'label'].values[0]
            result = "Phishing(saved)" if label == -1 else "Safe(saved)"
        else:
            # Predict using the model if URL is not in the database
            feature_values = list(features.values())
            prediction = model.predict([feature_values])[0]
            result = "Phishing" if prediction == -1 else "Safe"

            # Append the new URL and its label to the DataFrame
            new_data = pd.DataFrame([[url, prediction]], columns=['url', 'label'])
            df = pd.concat([df, new_data], ignore_index=True)

            # Save the updated DataFrame to the CSV file
            save_to_csv(df)

        history_data = {
            'userId': user_id,
            'url': url,
            'result': result,
            #'features': features,
            #'timestamp': pd.Timestamp.now()  # Add a timestamp for tracking
        }
        history_collection.insert_one(history_data)
        history_records = list(
        history_collection.find({'userId': user_id})
        .sort('_id', -1)  # Sort by _id in descending order to get the most recent entries first
        .limit(10)        # Limit the results to the last 12 entries
        )
        print(history_records) 
        # Render the result in the template
        return render_template('Dashboard.html', url=url, result=result, features=features, email=email, history=history_records)
        
    # Render the dashboard on GET request
    return render_template('Dashboard.html', email=email, history=history_records)



@app.route('/signup', methods=['POST'])
def signup():
    name = request.form.get('name')

    occupation = request.form.get('occupation')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirmPassword')
    
    # Validate the password confirmation
    if password != confirm_password:
        return "Passwords do not match", 400  # Return an error message if passwords don't match
    
    # Hash the password for security
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Insert the new user record in the MongoDB
    user_data = {
        "name": name,
        "occupation": occupation,
        "email": email,
        "password": hashed_password
    }
    
    # Check if the user already exists by email
    if db.users.find_one({"email": email}):
        return "Email already registered", 400
    
    db.users.insert_one(user_data)
    
    return redirect('/login')



@app.route('/logout')
def logout():
    # Redirect to the login page
    return redirect('http://localhost:3000/')

if __name__ == '__main__':
    app.run(debug=True)
