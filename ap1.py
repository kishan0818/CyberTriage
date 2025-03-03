from flask import Flask, request, render_template, jsonify
import pandas as pd
import joblib
import os
import scapy.all as scapy
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model

app = Flask(__name__)

# Load the trained ML models
csv_model_path = "csv_ml_model.pkl"
pcap_model_path = "pcap_ml_model.pkl"

if not os.path.exists(csv_model_path) or not os.path.exists(pcap_model_path):
    raise FileNotFoundError("Trained model files not found!")

csv_model = joblib.load(csv_model_path)
pcap_model = joblib.load(pcap_model_path)

def extract_features_from_pcap(file_path):
    packets = scapy.rdpcap(file_path)
    features = []
    for packet in packets:
        if scapy.IP in packet:
            features.append([
                packet[scapy.IP].src,
                packet[scapy.IP].dst,
                len(packet),
                packet[scapy.IP].proto,
            ])
    return np.array(features)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload_csv', methods=['POST'])
def upload_csv():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    try:
        df = pd.read_csv(file)
        feature_names = csv_model.feature_names_in_
        if not all(col in df.columns for col in feature_names):
            return jsonify({"error": "CSV file must contain required columns"}), 400
        X = df[feature_names].values
        df['Risk Level'] = csv_model.predict(X)
        return render_template('results.html', results=df.to_dict(orient='records'))
    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"}), 500

@app.route('/upload_pcap', methods=['POST'])
def upload_pcap():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400
    
    try:
        file_path = os.path.join("uploads", file.filename)
        file.save(file_path)
        features = extract_features_from_pcap(file_path)
        predictions = pcap_model.predict(features)
        return jsonify({"predictions": predictions.tolist()})
    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
