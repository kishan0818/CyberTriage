# Model training code for the DDoS attack detection system

import pandas as pd
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix, classification_report

# Paths
DATASET_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_dataset.csv"
MODEL_PATH = "/content/drive/MyDrive/Cybertriage/ddos_attack_model.pkl"
ENCODER_PATH = "/content/drive/MyDrive/Cybertriage/label_encoder.pkl"

# Load dataset
df = pd.read_csv(DATASET_PATH)
df.columns = df.columns.str.strip()

# Encode categorical data
df["Subnet"] = df["Subnet"].map({"same": 0, "different": 1})

label_encoder = LabelEncoder()
df["Attack_Type"] = label_encoder.fit_transform(df["Attack_Type"])

# Prepare features and target
X = df.drop(columns=["IP", "Attack_Type"])
y = df["Attack_Type"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Predictions
y_pred = model.predict(X_test)

# Accuracy and F1 Score
accuracy = accuracy_score(y_test, y_pred)
f1 = f1_score(y_test, y_pred, average="weighted")
print(f"Model Accuracy: {accuracy * 100:.2f}%")
print(f"Weighted F1 Score: {f1:.2f}\n")

# Detailed Classification Report
report = classification_report(y_test, y_pred, target_names=label_encoder.classes_)
print("Classification Report:\n")
print(report)

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues", xticklabels=label_encoder.classes_, yticklabels=label_encoder.classes_)
plt.xlabel("Predicted")
plt.ylabel("Actual")
plt.title("Confusion Matrix")
plt.show()
print('\n')

# Accuracy Graph
train_acc = model.score(X_train, y_train)
test_acc = model.score(X_test, y_test)

plt.figure(figsize=(6, 4))
plt.bar(["Train Accuracy", "Test Accuracy"], [train_acc, test_acc], color=["green", "blue"])
plt.ylim(0, 1)
plt.ylabel("Accuracy")
plt.title("Training vs Testing Accuracy")
plt.show()

# Save model and encoder
joblib.dump(model, MODEL_PATH)
joblib.dump(label_encoder, ENCODER_PATH)
print(f"Model saved to: {MODEL_PATH}")
print(f"Label Encoder saved to: {ENCODER_PATH}")
