# Predict code

import pandas as pd
import joblib

MODEL_PATH = "models/classification_model.pkl"
ENCODER_PATH = "models/label_encoder.pkl"
TRAIN_DATA_PATH = "ddos_attack_dataset.csv"

def predict_attack(new_data_file):
    model = joblib.load(MODEL_PATH)
    label_encoder = joblib.load(ENCODER_PATH)

    new_data = pd.read_csv(new_data_file)
    new_data.columns = new_data.columns.str.strip()

    if "Subnet" in new_data.columns:
        new_data["Subnet"] = new_data["Subnet"].map({"same": 0, "different": 1})
    else:
        print("⚠ Warning: 'Subnet' column is missing in the input file. Filling with default value (0).")
        new_data["Subnet"] = 0

    ip_addresses = new_data["IP"] if "IP" in new_data.columns else ["Unknown"] * len(new_data)

    new_data = new_data.drop(columns=["IP", "Attack_Type"], errors="ignore")

    X_train = pd.read_csv(TRAIN_DATA_PATH)
    X_train.columns = X_train.columns.str.strip()
    X_train = X_train.drop(columns=["IP", "Attack_Type"], errors="ignore")

    new_data = new_data.reindex(columns=X_train.columns, fill_value=0)

    predictions = model.predict(new_data)
    predicted_attack_types = label_encoder.inverse_transform(predictions)

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

new_data_file = "predict.csv"
results = predict_attack(new_data_file)
print(results)
