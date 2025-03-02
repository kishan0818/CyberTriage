from flask import Flask, render_template, request, redirect, url_for, session, flash
import os
import pandas as pd
import numpy as np
from tensorflow.keras.models import load_model
import pickle
import random

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secure key

# Load the pre-trained model
MODEL_PATH = 'best_model.h5'
model = None

# Dictionary of valid credentials (in a real app, use a database)
USERS = {
    'admin': 'password123',
    'user': 'user123'
}

# Function to load the model
def load_ddos_model():
    global model
    try:
        model = load_model(MODEL_PATH)
        print("Model loaded successfully!")
        return True
    except Exception as e:
        print(f"Error loading model: {e}")
        return False

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('upload'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in USERS and USERS[username] == password:
        session['username'] = username
        return redirect(url_for('upload'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload')
def upload():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('results.html', username=session['username'], results=None)

@app.route('/upload', methods=['POST'])
def process_upload():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if 'file' not in request.files:
        flash('No file part')
        return redirect(url_for('upload'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No selected file')
        return redirect(url_for('upload'))
    
    if file and file.filename.endswith('.csv'):
        # Save file temporarily
        filepath = os.path.join('uploads', file.filename)
        os.makedirs('uploads', exist_ok=True)
        file.save(filepath)
        
        # Process the file and get results
        results = process_csv_file(filepath)
        
        # Clean up
        os.remove(filepath)
        
        # Calculate summary counts
        malicious_count = sum(1 for ip in results if ip['risk_level'] == 'High Risk')
        suspicious_count = sum(1 for ip in results if ip['risk_level'] == 'Suspicious')
        benign_count = sum(1 for ip in results if ip['risk_level'] == 'Normal')
        
        return render_template('results.html', 
                              username=session['username'], 
                              results=results,
                              malicious_count=malicious_count,
                              suspicious_count=suspicious_count,
                              benign_count=benign_count)
    else:
        flash('File must be a CSV')
        return redirect(url_for('upload'))

def process_csv_file(filepath):
    """Process the uploaded CSV file with the DDoS detection model"""
    # Ensure model is loaded
    if model is None:
        load_ddos_model()
    
    try:
        # Read CSV file
        df = pd.read_csv(filepath)
        
        # In a real app, you would:
        # 1. Preprocess the data
        # 2. Extract features
        # 3. Run the model to get predictions
        # 4. Process the results
        
        # For this example, we'll simulate results
        # In a real implementation, you would use:
        # predictions = model.predict(preprocessed_data)
        
        # Simulated IP addresses and results
        results = generate_sample_results(df)
        
        return results
        
    except Exception as e:
        print(f"Error processing file: {e}")
        # Return empty results in case of error
        return []

def generate_sample_results(df):
    """Generate sample results for demonstration purposes"""
    # In a real implementation, use the actual model predictions
    
    # Get unique IPs from the dataframe if it has an 'ip' column
    # Otherwise generate some random IPs
    if 'ip' in df.columns:
        ip_addresses = df['ip'].unique().tolist()
    else:
        # Generate 20 random IP addresses
        ip_addresses = [f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(20)]
    
    results = []
    risk_levels = ["High Risk", "Suspicious", "Normal"]
    risk_classes = ["danger", "warning", "success"]
    
    for ip in ip_addresses:
        # Randomly assign a risk level with bias towards normal traffic
        r = random.random()
        if r < 0.15:  # 15% chance for high risk
            risk_idx = 0
        elif r < 0.35:  # 20% chance for suspicious
            risk_idx = 1
        else:  # 65% chance for normal
            risk_idx = 2
        
        results.append({
            "address": ip,
            "risk_level": risk_levels[risk_idx],
            "risk_class": risk_classes[risk_idx],
            "confidence": round(random.uniform(70, 99), 1),
            "traffic": round(random.uniform(1, 500), 1)
        })
    
    # Sort by risk level (high risk first)
    results.sort(key=lambda x: risk_levels.index(x["risk_level"]))
    
    return results

if __name__ == '__main__':
    # Make sure uploads directory exists
    os.makedirs('uploads', exist_ok=True)
    
    # Try to load the model at startup
    load_ddos_model()
    
    app.run(debug=True)