from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import pandas as pd
import numpy as np
import random
import traceback
import joblib  # For loading ML models
import ipaddress  # For subnet extraction
import subprocess
import json
from datetime import datetime
import threading
import queue
import time
from collections import defaultdict

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a random secure key

# Dictionary of valid credentials
USERS = {
    'admin': 'password123',
    'user': 'user123'
}

# Path definitions
MODEL_PATH = 'models'  # Update this to your model directory
TRAIN_DATA_PATH = 'ddos_attack_dataset.csv'  # Path to training data for column alignment
BLOCKED_IPS_FILE = 'blocked_ips.json'

# Load ML models
try:
    # Load classification model
    classification_model = joblib.load(os.path.join(MODEL_PATH, 'classification_model.pkl'))
    # Load label encoder
    label_encoder = joblib.load(os.path.join(MODEL_PATH, 'label_encoder.pkl'))
    # Store the expected feature names from the model
    expected_features = classification_model.feature_names_in_ if hasattr(classification_model, 'feature_names_in_') else None
    print(f"ML models loaded successfully. Expected features: {expected_features}")
    print(f"Label encoder loaded. Classes: {label_encoder.classes_}")
except Exception as e:
    print(f"Error loading ML models: {e}")
    traceback.print_exc()
    classification_model = None
    label_encoder = None
    expected_features = None

# Add these global variables at the top with other constants
CAPTURE_ACTIVE = False
PACKET_QUEUE = queue.Queue()
MONITORING_RESULTS = []
MONITORING_LOCK = threading.Lock()

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('process_logs'))
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in USERS and USERS[username] == password:
        session['username'] = username
        return redirect(url_for('process_logs'))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/upload_dataset')
def upload_dataset():
    # Ensure this route redirects to process_logs
    return redirect(url_for('process_logs'))

@app.route('/process_logs', methods=['GET', 'POST'])
def process_logs():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    if request.method == 'POST':
        # Check if a file was uploaded
        if 'file' not in request.files:
            flash('No file uploaded')
            return redirect(url_for('upload'))
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(url_for('upload'))
        
        if not file.filename.endswith('.csv'):
            flash('Only CSV files are allowed')
            return redirect(url_for('upload'))
        
        try:
            # Save the uploaded file
            filepath = os.path.join('uploads', 'temp.csv')
            file.save(filepath)
            
            # Process the file
            results = predict_attack(filepath)
            
            if not results:
                if classification_model and label_encoder:
                    print("Falling back to ML model processing")
                    results = process_with_ml_model(filepath)
                else:
                    print("ML model not available, using direct processing")
                    results = process_csv_directly(filepath)
            
            # Calculate summary counts
            malicious_count = sum(1 for ip in results if ip['risk_level'] == 'High Risk')
            suspicious_count = sum(1 for ip in results if ip['risk_level'] == 'Suspicious')
            benign_count = sum(1 for ip in results if ip['risk_level'] == 'Normal')
            
            # Clean up the temporary file
            try:
                os.remove(filepath)
            except:
                pass
            
            return render_template('results.html',
                                username=session['username'],
                                results=results,
                                malicious_count=malicious_count,
                                suspicious_count=suspicious_count,
                                benign_count=benign_count)
            
        except Exception as e:
            print(f"Error processing uploaded file: {e}")
            traceback.print_exc()
            flash("Error processing the uploaded file")
            return redirect(url_for('upload'))
    
    # If GET request or no file uploaded, redirect to upload page
    return redirect(url_for('upload'))

def predict_attack(filepath):
    """Process the CSV file using the improved predict function"""
    try:
        print(f"Using predict_attack function on: {filepath}")
        
        # Check if model and encoder exist
        if not os.path.exists(os.path.join(MODEL_PATH, 'classification_model.pkl')) or \
           not os.path.exists(os.path.join(MODEL_PATH, 'label_encoder.pkl')) or \
           not os.path.exists(TRAIN_DATA_PATH):
            print("Required files for prediction are missing")
            return None
        
        # Load model and encoder
        model = joblib.load(os.path.join(MODEL_PATH, 'classification_model.pkl'))
        label_encoder = joblib.load(os.path.join(MODEL_PATH, 'label_encoder.pkl'))
        
        # Read the new data
        new_data = pd.read_csv(filepath)
        new_data.columns = new_data.columns.str.strip()
        
        print(f"New data columns: {new_data.columns.tolist()}")
        
        # Find IP column
        ip_column = None
        ip_pattern_columns = ['ip', 'source_ip', 'src_ip', 'source', 'address', 'src', 'IP', 'Src_IP']
        
        for col in ip_pattern_columns:
            if col in new_data.columns:
                ip_column = col
                break
        
        # If no IP column found, try to guess based on content
        if ip_column is None:
            for col in new_data.columns:
                if len(new_data) > 0:
                    val = str(new_data[col].iloc[0])
                    if '.' in val and sum(c.isdigit() for c in val) > 3:
                        ip_column = col
                        print(f"Guessing {col} as IP column based on data pattern")
                        break
        
        # If still no IP column, use placeholder
        if ip_column is None:
            print("No IP column found, using placeholder")
            new_data['IP'] = [f"192.168.1.{i % 255 + 1}" for i in range(len(new_data))]
            ip_column = 'IP'
        
        # Store IP addresses
        ip_addresses = new_data[ip_column].tolist()
        
        # Handle subnet column
        if "Subnet" in new_data.columns:
            new_data["Subnet"] = new_data["Subnet"].map({"same": 0, "different": 1})
        else:
            print("⚠ Warning: 'Subnet' column is missing in the input file. Filling with default value (0).")
            new_data["Subnet"] = 0
        
        # Load training data for column alignment
        try:
            X_train = pd.read_csv(TRAIN_DATA_PATH)
            X_train.columns = X_train.columns.str.strip()
            X_train = X_train.drop(columns=["IP", "Attack_Type"], errors="ignore")
            
            # Prepare input data
            input_data = new_data.copy()
            
            # Drop IP and Attack_Type if present
            input_data = input_data.drop(columns=[ip_column, "Attack_Type"], errors="ignore")
            
            # Make sure columns match training data
            input_data = input_data.reindex(columns=X_train.columns, fill_value=0)
            
            print(f"Input data shape: {input_data.shape}, columns: {input_data.columns.tolist()}")
            
            # Make predictions
            predictions = model.predict(input_data)
            predicted_attack_types = label_encoder.inverse_transform(predictions)
            
            # Find amplification factor column
            amp_col = next((col for col in input_data.columns if "amplification" in col.lower()), None)
            if amp_col is None:
                amp_col = "Amplification_Factor"
                input_data[amp_col] = 1.0  # Default value
            
            # Calculate risk factors
            if input_data[amp_col].max() != input_data[amp_col].min():
                risk_factors = ((input_data[amp_col] - input_data[amp_col].min()) / 
                               (input_data[amp_col].max() - input_data[amp_col].min()) * 100).round(2)
            else:
                risk_factors = pd.Series([50.0] * len(input_data))  # Default risk if all values are the same
            
            # Create results in the format expected by the template
            results = []
            for i, ip in enumerate(ip_addresses):
                attack_type = predicted_attack_types[i]
                risk_factor = risk_factors.iloc[i]
                
                # Determine risk level based on risk factor
                if risk_factor < 50:
                    risk_level = "Normal"
                    risk_class = "success"
                    display_attack_type = "Normal"
                elif 50 <= risk_factor <= 80:
                    risk_level = "Suspicious"
                    risk_class = "warning"
                    display_attack_type = f"Potential {attack_type}" if attack_type.lower() != "normal" else "Normal"
                else:
                    risk_level = "High Risk"
                    risk_class = "danger"
                    display_attack_type = attack_type
                
                # Calculate traffic (sum of packet counts)
                traffic_sum = 0
                for col in ['TCP_Packet_Count', 'UDP_Packet_Count', 'ICMP_Packet_Count']:
                    col_alt = col.replace('_Packet_Count', '_Packets')
                    if col in input_data.columns:
                        traffic_sum += float(input_data.iloc[i][col]) if i < len(input_data) else 0
                    elif col_alt in input_data.columns:
                        traffic_sum += float(input_data.iloc[i][col_alt]) if i < len(input_data) else 0
                
                results.append({
                    "address": str(ip),
                    "attack_type": display_attack_type,
                    "risk_level": risk_level,
                    "risk_class": risk_class,
                    "confidence": round(float(risk_factor), 1),
                    "traffic": round(float(traffic_sum), 1)
                })
            
            # Sort by risk level (high risk first)
            results.sort(key=lambda x: {"High Risk": 0, "Suspicious": 1, "Normal": 2}[x["risk_level"]])
            
            return results
            
        except Exception as e:
            print(f"Error in predict_attack column alignment: {e}")
            traceback.print_exc()
            return None
            
    except Exception as e:
        print(f"Error in predict_attack: {e}")
        traceback.print_exc()
        return None

def extract_subnet(ip_address):
    """Extract subnet from IP address (first three octets)"""
    try:
        # Get first 24 bits for IPv4 (first three octets)
        parts = str(ip_address).split('.')
        if len(parts) == 4:
            subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
            return subnet
        return '0.0.0.0'  # Default for non-IPv4 format
    except:
        return '0.0.0.0'  # Default for invalid IPs

def subnet_to_int(subnet_str):
    """Convert subnet string to integer representation for the model"""
    try:
        # Convert IP string to integer value
        ip_obj = ipaddress.IPv4Address(subnet_str)
        return int(ip_obj)
    except:
        return 0

def process_with_ml_model(filepath):
    """Process the CSV file using the ML model"""
    print(f"Processing CSV file: {filepath}")
    
    # Read the CSV file
    df = pd.read_csv(filepath)
    print(f"CSV loaded successfully with {len(df)} rows and columns: {df.columns.tolist()}")
    
    # Print first few rows to understand the data
    print(f"Sample data:\n{df.head()}")
    
    # Find IP column
    ip_column = None
    ip_pattern_columns = ['ip', 'source_ip', 'src_ip', 'source', 'address', 'src', 'IP', 'Src_IP']
    
    for col in ip_pattern_columns:
        if col in df.columns:
            ip_column = col
            break
    
    # If no obvious IP column, try to guess based on the data
    if ip_column is None:
        for col in df.columns:
            # Check first value if it looks like an IP address
            if len(df) > 0:
                val = str(df[col].iloc(0))
                if '.' in val and sum(c.isdigit() for c in val) > 3:
                    ip_column = col
                    print(f"Guessing {col} as IP column based on data pattern")
                    break
    
    if ip_column is None:
        print("No IP column found, using row indices")
        df['placeholder_ip'] = [f"192.168.1.{i % 255 + 1}" for i in range(len(df))]
        ip_column = 'placeholder_ip'
        
    print(f"Using {ip_column} as IP address column")
    
    try:
        # Prepare data for ML model
        print("Processing data with ML models")
        
        # Rename columns and prepare data
        processed_df = df.copy()
        
        # Map old column names to new names if needed
        column_mapping = {
            'TCP_Packets': 'TCP_Packet_Count',
            'UDP_Packets': 'UDP_Packet_Count',
            'ICMP_Packets': 'ICMP_Packet_Count'
        }
        
        # Rename columns based on mapping
        for old_col, new_col in column_mapping.items():
            if old_col in processed_df.columns and new_col not in processed_df.columns:
                processed_df[new_col] = processed_df[old_col]
        
        # Extract subnet from IP address
        if ip_column:
            processed_df['Subnet'] = processed_df[ip_column].apply(extract_subnet)
            # Convert subnet to numeric value for the model
            processed_df['Subnet_Numeric'] = processed_df['Subnet'].apply(subnet_to_int)
        else:
            processed_df['Subnet'] = '0.0.0.0'  # Default if no IP column found
            processed_df['Subnet_Numeric'] = 0
        
        # Make sure all required features exist
        if 'Amplification_Factor' not in processed_df.columns and 'Amplification_Factor' in df.columns:
            processed_df['Amplification_Factor'] = df['Amplification_Factor']
        elif 'Amplification_Factor' not in processed_df.columns:
            processed_df['Amplification_Factor'] = 0  # Default value
            
        # Get the model's expected features
        global expected_features
        if expected_features is None and hasattr(classification_model, 'feature_names_in_'):
            expected_features = classification_model.feature_names_in_
            
        print(f"Model expects these features: {expected_features}")
        
        # Create feature matrix matching the model's expected features
        X = pd.DataFrame(index=processed_df.index)
        
        # Handle the Subnet feature - replace with numeric version
        for feature in expected_features:
            if feature == 'Subnet':
                X[feature] = processed_df['Subnet_Numeric']
            elif feature in processed_df.columns:
                X[feature] = processed_df[feature]
            elif feature.startswith('Subnet_'):
                # Handle one-hot encoded subnet features
                subnet_value = feature.split('_', 1)[1]
                X[feature] = (processed_df['Subnet'] == subnet_value).astype(int)
            else:
                X[feature] = 0  # Default for missing features
        
        # Ensure all columns are present and in the correct order
        missing_features = set(expected_features) - set(X.columns)
        if missing_features:
            print(f"Missing features: {missing_features}")
            for feature in missing_features:
                X[feature] = 0
        
        # Ensure columns are in the correct order
        X = X[expected_features]
        
        print(f"X shape: {X.shape}, features: {X.columns.tolist()}")
        print(f"X data types: {X.dtypes}")
        
        # Convert all data to float for the model
        X = X.astype(float)
        
        # Make predictions
        predictions_raw = classification_model.predict(X)
        
        # If we have a label encoder, use it to interpret the predictions
        global label_encoder
        if label_encoder is not None:
            attack_types = label_encoder.inverse_transform(predictions_raw)
            print(f"Predicted classes after inverse transform: {set(attack_types)}")
        else:
            # If no label encoder, use raw predictions
            attack_types = predictions_raw
            print(f"Raw predictions (no label encoder): {set(attack_types)}")
        
        # Get prediction probabilities if available
        try:
            probabilities = classification_model.predict_proba(X)
            confidence_scores = np.max(probabilities, axis=1) * 100
        except:
            confidence_scores = np.random.uniform(70, 99, len(predictions_raw))
        
        # Create results with specific attack types
        results = []
        for i, ip in enumerate(df[ip_column]):
            # Get the predicted attack type
            attack_type = attack_types[i]
            
            # Normalize attack type
            if isinstance(attack_type, (int, np.integer)):
                # If numeric, map to attack type names
                attack_map = {
                    0: "Normal",
                    1: "DoS", 
                    2: "DDoS",
                    3: "DRDoS",
                    4: "APDoS"
                }
                attack_name = attack_map.get(int(attack_type), "Suspicious")
            else:
                # If string, use as is but capitalize properly
                attack_name = str(attack_type).capitalize()
                if attack_name.lower() in ["normal", "benign"]:
                    attack_name = "Normal"
                elif attack_name.lower() == "dos":
                    attack_name = "DoS"
                elif attack_name.lower() == "ddos":
                    attack_name = "DDoS"
                elif attack_name.lower() == "drdos":
                    attack_name = "DRDoS"
                elif attack_name.lower() == "apdos":
                    attack_name = "APDoS"
                else:
                    attack_name = "Suspicious"
            
            # Calculate total traffic
            traffic_sum = 0
            for col in ['TCP_Packet_Count', 'UDP_Packet_Count', 'ICMP_Packet_Count']:
                if col in processed_df.columns:
                    traffic_sum += processed_df.loc[i, col] if i < len(processed_df) else 0
                elif col.replace('_Packet_Count', '_Packets') in processed_df.columns:
                    traffic_sum += processed_df.loc[i, col.replace('_Packet_Count', '_Packets')] if i < len(processed_df) else 0
            
            # NEW CODE: Evaluate confidence score and assign risk level based on it
            confidence = float(confidence_scores[i])
            
            if confidence < 50:
                # Below 50% confidence, treat as normal regardless of attack type
                risk_level = "Normal"
                risk_class = "success"
                display_attack_type = "Normal"
            elif 60 <= confidence <= 80:
                # Between 60-80% confidence, mark as "Potential <attack_type>"
                risk_level = "Suspicious"
                risk_class = "warning"
                display_attack_type = f"Potential {attack_name}" if attack_name != "Normal" else "Normal"
            elif confidence > 80:
                # Above 80% confidence, mark as high risk with the attack type
                risk_level = "High Risk"
                risk_class = "danger" 
                display_attack_type = attack_name
            else:
                # For confidence between 50-60%, keep behavior similar to 60-80%
                risk_level = "Suspicious"
                risk_class = "warning"
                display_attack_type = f"Potential {attack_name}" if attack_name != "Normal" else "Normal"
            
            results.append({
                "address": str(ip),
                "attack_type": display_attack_type,  # Using the modified attack type display
                "risk_level": risk_level,
                "risk_class": risk_class,
                "confidence": round(confidence, 1),
                "traffic": round(float(traffic_sum), 1)
            })
        
        # Sort by risk level (high risk first)
        results.sort(key=lambda x: {"High Risk": 0, "Suspicious": 1, "Normal": 2}[x["risk_level"]])
        
        return results
    
    except Exception as e:
        print(f"Error using ML model: {e}")
        traceback.print_exc()
        print("Falling back to direct processing method")
        return process_csv_directly(filepath)

def process_csv_directly(filepath):
    """Process the CSV file directly without using ML model"""
    print(f"Processing CSV file directly: {filepath}")
    
    # Read the CSV file
    df = pd.read_csv(filepath)
    print(f"CSV loaded successfully with {len(df)} rows and columns: {df.columns.tolist()}")
    
    # Print first few rows to understand the data
    print(f"Sample data:\n{df.head()}")
    
    # Try to identify IP column
    ip_column = None
    ip_pattern_columns = ['ip', 'source_ip', 'src_ip', 'source', 'address', 'src', 'IP', 'Src_IP']
    
    for col in ip_pattern_columns:
        if col in df.columns:
            ip_column = col
            break
    
    # If no obvious IP column, try to guess based on the data
    if ip_column is None:
        for col in df.columns:
            # Check first value if it looks like an IP address
            if len(df) > 0:
                val = str(df[col].iloc(0))
                if '.' in val and sum(c.isdigit() for c in val) > 3:
                    ip_column = col
                    print(f"Guessing {col} as IP column based on data pattern")
                    break
    
    # Still no IP column? Use index as placeholder
    if ip_column is None:
        print("No IP column found, using row indices")
        df['placeholder_ip'] = [f"192.168.1.{i % 255 + 1}" for i in range(len(df))]
        ip_column = 'placeholder_ip'
    
    print(f"Using {ip_column} as IP address column")
    
    # Map expected column names to actual ones
    traffic_column_map = {
        'TCP_Packet_Count': ['TCP_Packets', 'tcp_packets', 'tcp_count'],
        'UDP_Packet_Count': ['UDP_Packets', 'udp_packets', 'udp_count'],
        'ICMP_Packet_Count': ['ICMP_Packets', 'icmp_packets', 'icmp_count']
    }
    
    # Create standardized columns
    for std_col, possible_cols in traffic_column_map.items():
        if std_col not in df.columns:
            for possible_col in possible_cols:
                if possible_col in df.columns:
                    df[std_col] = df[possible_col]
                    break
            if std_col not in df.columns:
                df[std_col] = 0  # Default if no matching column found
    
    # Try to identify potential DDoS indicators
    # Use standardized columns and any additional numeric columns
    traffic_columns = ['TCP_Packet_Count', 'UDP_Packet_Count', 'ICMP_Packet_Count', 'Amplification_Factor']
    
    # Find all numeric columns for analysis
    numeric_columns = df.select_dtypes(include=['number']).columns.tolist()
    selected_columns = [col for col in traffic_columns if col in df.columns]
    
    # Add any other numeric columns that might be relevant
    for col in numeric_columns:
        if col not in selected_columns and col != ip_column:
            selected_columns.append(col)
    
    print(f"Using columns for traffic analysis: {selected_columns}")
    
    # For threshold-based detection
    threshold_values = {}
    
    # For each selected column, calculate threshold for abnormal values
    for col in selected_columns:
        if col in df.columns:
            values = df[col].dropna()
            if len(values) > 0:
                # Using mean + 2*std as threshold for suspicious and mean + 3*std for malicious
                mean_val = values.mean()
                std_val = values.std()
                if std_val > 0:  # Avoid division by zero
                    threshold_values[col] = {
                        'suspicious': mean_val + 1.4 * std_val,
                        'malicious': mean_val + 1.8 * std_val
                    }
                    print(f"For {col}: suspicious > {threshold_values[col]['suspicious']}, malicious > {threshold_values[col]['malicious']}")
    
    # Process by IP address
    results = []
    
    # Get unique IPs
    unique_ips = df[ip_column].dropna().unique()
    
    # For each IP, analyze its traffic patterns
    for ip in unique_ips:
        ip_data = df[df[ip_column] == ip]
        
        # Track risk score
        risk_score = 0
        max_score = 0
        metrics = {}
        
        # Analyze each selected column
        for col in selected_columns:
            if col in df.columns and col in threshold_values:
                col_value = ip_data[col].sum()  # Sum all values for this IP
                metrics[col] = col_value
                
                # Calculate risk based on threshold
                if col_value > threshold_values[col]['malicious']:
                    risk_score += 3
                elif col_value > threshold_values[col]['suspicious']:
                    risk_score += 1
                
                max_score += 3  # Maximum possible score for this column
        
        # Normalize risk score to 0-1 range
        normalized_risk = risk_score / max(max_score, 1)
        
        # Determine traffic volume (sum of packet counts)
        traffic_volume = 0
        for col in ['TCP_Packet_Count', 'UDP_Packet_Count', 'ICMP_Packet_Count']:
            if col in ip_data.columns:
                traffic_volume += ip_data[col].sum()
        
        # Calculate confidence percentage
        confidence = normalized_risk * 100
        
        # NEW CODE: Classify risk based on confidence percentage
        if confidence < 50:
            risk_level = "Normal"
            risk_class = "success"
            attack_type = "Normal"
        elif 60 <= confidence <= 80:
            risk_level = "Suspicious"
            risk_class = "warning"
            # Determine attack type based on traffic patterns
            if ip_data.get('TCP_Packet_Count', 0).sum() > ip_data.get('UDP_Packet_Count', 0).sum():
                attack_type = "Potential TCP Flood"
            elif ip_data.get('UDP_Packet_Count', 0).sum() > ip_data.get('ICMP_Packet_Count', 0).sum():
                attack_type = "Potential UDP Flood"
            else:
                attack_type = "Potential Suspicious Activity"
        elif confidence > 80:
            risk_level = "High Risk"
            risk_class = "danger"
            # Assign specific attack type for high confidence
            if ip_data.get('TCP_Packet_Count', 0).sum() > ip_data.get('UDP_Packet_Count', 0).sum():
                attack_type = "TCP DDoS"
            elif ip_data.get('UDP_Packet_Count', 0).sum() > ip_data.get('ICMP_Packet_Count', 0).sum():
                attack_type = "UDP DDoS"
            else:
                attack_type = "DDoS"
        else:
            # For confidence between 50-60%
            risk_level = "Suspicious"
            risk_class = "warning"
            attack_type = "Potential Anomaly"
        
        # Add to results
        results.append({
            "address": str(ip),
            "attack_type": attack_type,
            "risk_level": risk_level,
            "risk_class": risk_class,
            "confidence": round(confidence, 1),
            "traffic": round(float(traffic_volume), 1)
        })
    
    # Sort by risk level (high risk first)
    results.sort(key=lambda x: {"High Risk": 0, "Suspicious": 1, "Normal": 2}[x["risk_level"]])
    
    # If no results (empty dataframe or processing error), generate some sample data
    if not results:
        print("No valid results extracted, generating sample data")
        results = generate_sample_results()
    
    return results

def generate_sample_results():
    """Generate sample results as fallback"""
    print("Generating sample results")
    
    # Generate 20 random IP addresses
    ip_addresses = [f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}" for _ in range(20)]
    
    results = []
    
    for ip in ip_addresses:
        # Randomly assign a confidence level
        confidence = random.uniform(30, 95)
        # NEW CODE: Determine risk level and attack type based on confidence
        if confidence < 50:
            risk_level = "Normal"
            risk_class = "success"
            attack_type = "Normal"
        elif 60 <= confidence <= 80:
            risk_level = "Suspicious"
            risk_class = "warning"
            attack_types = ["Potential TCP Flood", "Potential UDP Flood", "Potential Scanning"]
            attack_type = random.choice(attack_types)
        elif confidence > 80:
            risk_level = "High Risk"
            risk_class = "danger"
            attack_types = ["DDoS", "TCP DDoS", "UDP DDoS", "Amplification Attack"]
            attack_type = random.choice(attack_types)
        else:
            # For confidence between 50-60%
            risk_level = "Suspicious"
            risk_class = "warning"
            attack_type = "Potential Anomaly"
        
        results.append({
            "address": ip,
            "attack_type": attack_type,
            "risk_level": risk_level,
            "risk_class": risk_class,
            "confidence": round(confidence, 1),
            "traffic": round(random.uniform(1, 500), 1)
        })
    
    # Sort by risk level (high risk first)
    results.sort(key=lambda x: {"High Risk": 0, "Suspicious": 1, "Normal": 2}[x["risk_level"]])
    
    return results

@app.route('/block_ip', methods=['POST'])
def block_ip():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    ip_address = request.form.get('ip')
    if not ip_address:
        return json.dumps({'success': False, 'message': 'No IP address provided'}), 400
    
    try:
        # Check if the IP is already blocked
        blocked_ips = load_blocked_ips()
        if any(entry['ip'] == ip_address for entry in blocked_ips):
            return json.dumps({'success': False, 'message': 'IP is already blocked'}), 400
        
        # Create Windows Firewall rule with elevated privileges
        rule_name = f"Block-IP-{ip_address.replace('.', '-')}"
        
        # Create a PowerShell script file
        ps_script = f"""
$ErrorActionPreference = 'Stop'
try {{
    # Check if rule already exists
    $existingRule = Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue
    if ($existingRule) {{
        Write-Output "Rule already exists"
        exit 0
    }}
    
    # Create new rule
    New-NetFirewallRule -DisplayName "{rule_name}" -Direction Inbound -Action Block -RemoteAddress {ip_address} -Profile Any -Enabled True
    Write-Output "Rule created successfully"
    exit 0
}} catch {{
    Write-Error $_.Exception.Message
    exit 1
}}
"""
        script_path = os.path.join(os.getcwd(), 'block_ip.ps1')
        with open(script_path, 'w') as f:
            f.write(ps_script)
        
        # Run PowerShell script with elevated privileges using runas
        command = [
            'powershell.exe',
            '-ExecutionPolicy', 'Bypass',
            '-Command',
            f'Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -File {script_path}" -Wait'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Clean up the script file
        try:
            os.remove(script_path)
        except:
            pass
        
        # Check if the rule was created successfully by trying to get it
        verify_command = [
            'powershell.exe',
            '-Command',
            f'Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue'
        ]
        
        verify_result = subprocess.run(verify_command, capture_output=True, text=True)
        
        if verify_result.returncode == 0 and verify_result.stdout.strip():
            # Rule exists, save to blocked IPs file
            blocked_ips.append({
                'ip': ip_address,
                'rule_name': rule_name,
                'date_blocked': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'blocked_by': session['username'],
                'reason': request.form.get('reason', 'Manual block')
            })
            save_blocked_ips(blocked_ips)
            
            return json.dumps({'success': True, 'message': f'IP {ip_address} has been blocked'}), 200
        else:
            return json.dumps({
                'success': False, 
                'message': 'Failed to verify firewall rule creation. Please try running the application as administrator.'
            }), 500
    
    except Exception as e:
        print(f"Error in block_ip: {e}")
        traceback.print_exc()
        error_msg = str(e)
        if "Access is denied" in error_msg:
            error_msg = "Access denied. Please run the application as administrator."
        return json.dumps({'success': False, 'message': f'Error: {error_msg}'}), 500

@app.route('/unblock_ip', methods=['POST'])
def unblock_ip():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    ip_address = request.form.get('ip')
    if not ip_address:
        return json.dumps({'success': False, 'message': 'No IP address provided'}), 400
    
    try:
        # Find the rule name from our records
        blocked_ips = load_blocked_ips()
        rule_name = None
        
        for i, entry in enumerate(blocked_ips):
            if entry['ip'] == ip_address:
                rule_name = entry['rule_name']
                blocked_ips.pop(i)
                break
        
        if not rule_name:
            return json.dumps({'success': False, 'message': 'IP not found in blocked list'}), 400
        
        # Create PowerShell script for removal with better error handling and logging
        ps_script = f"""
$ErrorActionPreference = 'Stop'
$VerbosePreference = 'Continue'

try {{
    # Check if rule exists first
    $rule = Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue
    
    if ($rule) {{
        Write-Verbose "Found rule {rule_name}, attempting to remove..."
        Remove-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction Stop
        Write-Output "SUCCESS: Rule removed successfully"
        exit 0
    }} else {{
        Write-Output "SUCCESS: Rule not found (already removed)"
        exit 0
    }}
}} catch {{
    $errorMessage = $_.Exception.Message
    Write-Error "ERROR: $errorMessage"
    if ($errorMessage -like "*Access is denied*") {{
        Write-Error "ADMIN_REQUIRED"
    }}
    exit 1
}}
"""
        script_path = os.path.join(os.getcwd(), 'unblock_ip.ps1')
        with open(script_path, 'w') as f:
            f.write(ps_script)
        
        # Run PowerShell script with elevated privileges
        command = [
            'powershell.exe',
            '-ExecutionPolicy', 'Bypass',
            '-Command',
            f'Start-Process powershell.exe -Verb RunAs -ArgumentList "-ExecutionPolicy Bypass -NoProfile -File {script_path}" -Wait -WindowStyle Hidden'
        ]
        
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Clean up the script file
        try:
            os.remove(script_path)
        except:
            pass
        
        # Check if the rule still exists
        verify_command = [
            'powershell.exe',
            '-Command',
            f'(Get-NetFirewallRule -DisplayName "{rule_name}" -ErrorAction SilentlyContinue) -eq $null'
        ]
        
        verify_result = subprocess.run(verify_command, capture_output=True, text=True)
        
        # If the verification command returns True (as text), it means the rule is gone
        if verify_result.stdout.strip().lower() == 'true':
            # Rule was successfully removed, update blocked IPs file
            save_blocked_ips(blocked_ips)
            return json.dumps({'success': True, 'message': f'IP {ip_address} has been unblocked'}), 200
        else:
            # Check if it's an admin rights issue
            if "ADMIN_REQUIRED" in result.stderr:
                return json.dumps({
                    'success': False,
                    'message': 'Administrator privileges required. Please run the application as administrator.'
                }), 403
            else:
                return json.dumps({
                    'success': False,
                    'message': 'Failed to remove firewall rule. Please check Windows Firewall settings or try again.'
                }), 500
    
    except Exception as e:
        print(f"Error in unblock_ip: {e}")
        traceback.print_exc()
        error_msg = str(e)
        if "Access is denied" in error_msg:
            error_msg = "Access denied. Please run the application as administrator."
        elif "ADMIN_REQUIRED" in error_msg:
            error_msg = "Administrator privileges required. Please run the application as administrator."
        return json.dumps({'success': False, 'message': f'Error: {error_msg}'}), 500

@app.route('/blocked_ips')
def blocked_ips_page():
    if 'username' not in session:
        return redirect(url_for('index'))
    
    blocked_ips = load_blocked_ips()
    return render_template('blocked_ips.html', username=session['username'], blocked_ips=blocked_ips)

def load_blocked_ips():
    """Load the list of blocked IPs from JSON file"""
    if os.path.exists(BLOCKED_IPS_FILE):
        try:
            with open(BLOCKED_IPS_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading blocked IPs file: {e}")
            # Create an empty file on error
            with open(BLOCKED_IPS_FILE, 'w') as f:
                json.dump([], f)
    else:
        # Create the file if it doesn't exist
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump([], f)
    return []

def save_blocked_ips(blocked_ips):
    """Save the list of blocked IPs to JSON file"""
    try:
        with open(BLOCKED_IPS_FILE, 'w') as f:
            json.dump(blocked_ips, f, indent=2)
    except Exception as e:
        print(f"Error saving blocked IPs file: {e}")

def get_tshark_path():
    """Get the full path to tshark executable"""
    # Common Wireshark installation paths on Windows
    possible_paths = [
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        # Add the path from your Wireshark installation if different
    ]
    
    for path in possible_paths:
        if os.path.exists(path):
            return path
    
    return None

def capture_packets():
    """Capture packets using tshark and process them"""
    global CAPTURE_ACTIVE
    
    print("Starting packet capture...")
    
    # Get tshark path
    tshark_path = get_tshark_path()
    if not tshark_path:
        print("Error: tshark not found. Please install Wireshark or provide the correct path.")
        CAPTURE_ACTIVE = False
        return
    
    print(f"Found tshark at: {tshark_path}")
    
    # First list available interfaces
    try:
        interfaces_cmd = [tshark_path, '-D']
        interfaces = subprocess.run(interfaces_cmd, capture_output=True, text=True)
        print("Available interfaces:")
        print(interfaces.stdout)
    except Exception as e:
        print(f"Error listing interfaces: {e}")
    
    # Command to run tshark
    tshark_cmd = [
        tshark_path,  # Use full path to tshark
        '-i', '1',  # Interface number (change as needed)
        '-T', 'fields',
        '-E', 'separator=,',
        '-e', 'ip.src',
        '-e', 'ip.dst',
        '-e', 'tcp.srcport',
        '-e', 'tcp.dstport',
        '-e', 'udp.srcport',
        '-e', 'udp.dstport',
        '-e', 'icmp.type',
        '-e', '_ws.col.Protocol'
    ]
    
    try:
        print(f"Running tshark command: {' '.join(tshark_cmd)}")
        process = subprocess.Popen(
            tshark_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW  # Hide console window
        )
        
        # Check for immediate errors
        time.sleep(1)
        if process.poll() is not None:
            error = process.stderr.read()
            print(f"Tshark error: {error}")
            CAPTURE_ACTIVE = False
            return
        
        print("Tshark process started successfully")
        
        # Dictionary to store packet counts
        packet_counts = defaultdict(lambda: {
            'TCP_Packet_Count': 0,
            'UDP_Packet_Count': 0,
            'ICMP_Packet_Count': 0,
            'last_update': time.time()
        })
        
        print("Entering capture loop...")
        while CAPTURE_ACTIVE:
            line = process.stdout.readline()
            if not line:
                continue
            
            print(f"Raw packet data: {line.strip()}")
                
            fields = line.strip().split(',')
            if len(fields) < 8:
                print(f"Invalid packet data format: {fields}")
                continue
                
            src_ip, dst_ip, tcp_sport, tcp_dport, udp_sport, udp_dport, icmp_type, protocol = fields
            
            # Process source IP
            if src_ip:
                print(f"Processing packet from IP: {src_ip}, Protocol: {protocol}")
                if protocol == 'TCP':
                    packet_counts[src_ip]['TCP_Packet_Count'] += 1
                elif protocol == 'UDP':
                    packet_counts[src_ip]['UDP_Packet_Count'] += 1
                elif protocol == 'ICMP':
                    packet_counts[src_ip]['ICMP_Packet_Count'] += 1
                
                # Check if 30 seconds have passed for this IP
                current_time = time.time()
                if current_time - packet_counts[src_ip]['last_update'] >= 30:
                    print(f"30-second interval reached for IP: {src_ip}")
                    print(f"Packet counts: {packet_counts[src_ip]}")
                    
                    data = {
                        'IP': src_ip,
                        'TCP_Packet_Count': packet_counts[src_ip]['TCP_Packet_Count'],
                        'UDP_Packet_Count': packet_counts[src_ip]['UDP_Packet_Count'],
                        'ICMP_Packet_Count': packet_counts[src_ip]['ICMP_Packet_Count'],
                        'Subnet': 0,  # Default value
                        'Amplification_Factor': max(1.0, 
                            packet_counts[src_ip]['TCP_Packet_Count'] / 100.0 +
                            packet_counts[src_ip]['UDP_Packet_Count'] / 50.0 +
                            packet_counts[src_ip]['ICMP_Packet_Count'] / 10.0
                        )
                    }
                    
                    # Reset counters
                    packet_counts[src_ip] = {
                        'TCP_Packet_Count': 0,
                        'UDP_Packet_Count': 0,
                        'ICMP_Packet_Count': 0,
                        'last_update': current_time
                    }
                    
                    # Put data in queue for processing
                    print(f"Putting data in queue: {data}")
                    PACKET_QUEUE.put(data)
        
        print("Capture loop ended, terminating tshark...")
        process.terminate()
        
    except Exception as e:
        print(f"Error in capture_packets: {e}")
        traceback.print_exc()
        CAPTURE_ACTIVE = False

def process_packet_data():
    """Process packet data from queue and update monitoring results"""
    global MONITORING_RESULTS
    
    print("Starting packet data processing thread...")
    
    while CAPTURE_ACTIVE:
        try:
            # Get data from queue with a timeout of 1 second
            try:
                data = PACKET_QUEUE.get(timeout=1)
                print(f"Received data from queue: {data}")
            except queue.Empty:
                continue
            
            # Create DataFrame with single row
            df = pd.DataFrame([data])
            print(f"Created DataFrame: {df.head()}")
            
            # Process with ML model
            print("Processing with ML model...")
            results = process_with_ml_model(df)
            print(f"ML model results: {results}")
            
            if results:
                print(f"Updating monitoring results with: {results}")
                # Update monitoring results
                with MONITORING_LOCK:
                    # Remove old entry for this IP if exists
                    MONITORING_RESULTS = [r for r in MONITORING_RESULTS if r['address'] != data['IP']]
                    # Add new result
                    MONITORING_RESULTS.extend(results)
                    # Sort results
                    MONITORING_RESULTS.sort(key=lambda x: {"High Risk": 0, "Suspicious": 1, "Normal": 2}[x["risk_level"]])
                print(f"Current monitoring results: {MONITORING_RESULTS}")
            else:
                print("No results returned from ML model")
        
        except Exception as e:
            print(f"Error processing packet data: {e}")
            traceback.print_exc()

@app.route('/monitoring')
def monitoring():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('monitoring.html', username=session['username'])

@app.route('/start_monitoring', methods=['POST'])
def start_monitoring():
    global CAPTURE_ACTIVE
    
    if CAPTURE_ACTIVE:
        return jsonify({'success': False, 'message': 'Monitoring already active'})
    
    try:
        CAPTURE_ACTIVE = True
        
        # Start capture thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()
        
        # Start processing thread
        process_thread = threading.Thread(target=process_packet_data)
        process_thread.daemon = True
        process_thread.start()
        
        return jsonify({'success': True, 'message': 'Monitoring started'})
    
    except Exception as e:
        CAPTURE_ACTIVE = False
        return jsonify({'success': False, 'message': f'Error starting monitoring: {str(e)}'})

@app.route('/stop_monitoring', methods=['POST'])
def stop_monitoring():
    global CAPTURE_ACTIVE
    
    if not CAPTURE_ACTIVE:
        return jsonify({'success': False, 'message': 'Monitoring not active'})
    
    CAPTURE_ACTIVE = False
    return jsonify({'success': True, 'message': 'Monitoring stopped'})

@app.route('/get_monitoring_results')
def get_monitoring_results():
    with MONITORING_LOCK:
        return jsonify({
            'results': MONITORING_RESULTS,
            'is_active': CAPTURE_ACTIVE
        })

@app.route('/upload')
def upload():
    if 'username' not in session:
        return redirect(url_for('index'))
    return render_template('upload.html', username=session['username'])

if __name__ == '__main__':
    # Make sure uploads directory exists
    os.makedirs('uploads', exist_ok=True)
    
    # Make sure models directory exists
    os.makedirs(MODEL_PATH, exist_ok=True)
    
    # Set to debug mode for detailed error messages
    app.run(debug=True)