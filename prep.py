import pandas as pd
import joblib
from sklearn.preprocessing import MinMaxScaler, LabelEncoder

# Load the dataset (Use the same file you used during training)
df = pd.read_csv("network_logs.csv")

# Define the same feature columns
numerical_features = ['UDP_Packet_Count', 'TCP_Packet_Count', 'ICMP_Packet_Count', 'Amplification_Factor']
categorical_features = ['Subnet']
label_column = 'Attack_Type'

# Initialize scalers and encoders
scaler = MinMaxScaler()
encoder = LabelEncoder()
label_encoder = LabelEncoder()

# Fit the scaler and encoders using the same training dataset
df[numerical_features] = scaler.fit_transform(df[numerical_features])
df['Subnet'] = encoder.fit_transform(df['Subnet'])
df[label_column] = label_encoder.fit_transform(df[label_column])

# Save the fitted objects
joblib.dump(scaler, "scaler.pkl")
joblib.dump(encoder, "encoder.pkl")
joblib.dump(label_encoder, "label_encoder.pkl")

print("✅ Preprocessing objects saved successfully!")
