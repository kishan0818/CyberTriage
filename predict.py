# Cyber lab real time data

import pandas as pd
import joblib  # For model loading

# 📌 File Paths
MODEL_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_model.pkl"
ENCODER_PATH = "/content/drive/MyDrive/Cybertriage/label_encoder.pkl"
TRAIN_DATA_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_dataset.csv"

# 🔍 Predict Function
def predict_attack(new_data_file):
    # Load the trained model & label encoder
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)

    # Load the new dataset
    new_data = pd.read_csv(new_data_file)
    new_data.columns = new_data.columns.str.strip()  # Remove extra spaces from column names

    # ✅ Handle Missing "Subnet" Column Gracefully
    if "Subnet" in new_data.columns:
        new_data["Subnet"] = new_data["Subnet"].map({"same": 0, "different": 1})
    else:
        print("⚠ Warning: 'Subnet' column is missing in the input file. Filling with default value (0).")
        new_data["Subnet"] = 0  # Default value if missing

    # Store IP addresses for reference
    ip_addresses = new_data["IP"] if "IP" in new_data.columns else ["Unknown"] * len(new_data)

    # Drop IP & Attack_Type Columns (Not Needed for Prediction)
    new_data = new_data.drop(columns=["IP", "Attack_Type"], errors="ignore")

    # Load Training Data Column Order
    X_train = pd.read_csv(TRAIN_DATA_PATH)
    X_train.columns = X_train.columns.str.strip()
    X_train = X_train.drop(columns=["IP", "Attack_Type"], errors="ignore")  # Get only feature columns

    # Ensure Column Order Matches Training Data
    new_data = new_data.reindex(columns=X_train.columns, fill_value=0)

    # Predict Attack Type
    predictions = model.predict(new_data)
    predicted_attack_types = label_encoder.inverse_transform(predictions)

    # 🔥 Calculate Risk Factor (Based on Amplification Factor)
    amp_col = next((col for col in new_data.columns if "amplification" in col.lower()), None)
    if amp_col is None:
        raise KeyError("Amplification Factor column not found!")

    risk_factors = ((new_data[amp_col] - new_data[amp_col].min()) /
                    (new_data[amp_col].max() - new_data[amp_col].min()) * 100).round(2)

    # 🔹 Return Results
    results = pd.DataFrame({
        "IP": ip_addresses,
        "Predicted Attack Type": predicted_attack_types,
        "Risk Factor (0-100)": risk_factors
    })

    return results

# 📝 Example Usage
new_data_file = "/content/drive/MyDrive/Cybertriage/predict.csv"
results = predict_attack(new_data_file)
print(results)
