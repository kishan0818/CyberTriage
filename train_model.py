# Model training code

import pandas as pd
import joblib  # For model saving & loading
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score  # For accuracy calculation

# 📌 File Paths (Change if needed)
DATASET_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_dataset.csv"
MODEL_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_model.pkl"
ENCODER_PATH = "/content/drive/MyDrive/Cybertriage/label_encoder.pkl"

# 1️⃣ Load & Preprocess Dataset
df = pd.read_csv(DATASET_PATH)

# Fix Column Names
df.columns = df.columns.str.strip()

# Handle "Subnet" Column (Convert to 0/1)
df["Subnet"] = df["Subnet"].map({"same": 0, "different": 1})

# Convert Categorical "Attack_Type" into Numerical Labels
label_encoder = LabelEncoder()
df["Attack_Type"] = label_encoder.fit_transform(df["Attack_Type"])

# Features & Target
X = df.drop(columns=["IP", "Attack_Type"])  # Remove "IP" (not needed for ML)
y = df["Attack_Type"]

# Train-Test Split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 2️⃣ Train Random Forest Model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# 3️⃣ Model Accuracy Calculation
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"✅ Model Accuracy: {accuracy * 100:.2f}%")

# 4️⃣ Save Model & Label Encoder
joblib.dump(model, MODEL_PATH)
joblib.dump(label_encoder, ENCODER_PATH)
print(f"✅ Model saved to: {MODEL_PATH}")
print(f"✅ Label Encoder saved to: {ENCODER_PATH}")
