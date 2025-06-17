# AI-Powered Cyber Triage System for Real-Time Threat Detection

## Overview

The AI-Powered Cyber Triage System is a cybersecurity solution designed to detect and mitigate advanced network attacks such as DoS, DDoS, DRDoS, and APDoS in real time. Utilizing machine learning models and a user-friendly web interface, the system classifies threats from uploaded network logs and enables automated blocking of malicious IP addresses, significantly improving response time and accuracy.

## Smart Innovation Journey

This project was developed as part of our Mini Project. During development, we focused on creating an end-to-end automated solution, starting from log ingestion to actionable threat mitigation.

Early hurdles included:
- Model Training Accuracy vs. Real-Time Speed: We chose Random Forest for its low false positive rate while maintaining interpretability.
- Backend-Frontend Sync: Implemented Flask for seamless integration between ML models and the web interface.
- Real-Time Threat Handling: Created IP quarantine/blocking logic and UI management to deal with threats as they appear.

We proudly won First Prize in both the Paper Talks and Project Expo (Protovision) events during TECHNOVATE’25 at GCT, Coimbatore.

## Key Features

- Multi-Attack Detection – Detects DoS, DDoS, DRDoS, and APDoS threats.
- Live Network Monitoring – Observes packet flow in real time.
- ML-Powered Classification – Uses Random Forest and Decision Trees.
- User Dashboard – Shows attack type and risk levels with CSV upload support.
- IP Blocking – Automatically blocks or quarantines malicious IPs.
- Explainability – Model results are interpretable and traceable.
- TShark Integration (proposed) – Real-time packet analysis engine.


## How It Works

1. Upload Logs: Users upload `.csv` traffic logs via the web interface.
2. ML Inference: The backend classifies the type of attack.
3. Visualization: Displays type, severity, and threat source IP.
4. Response: IPs can be blocked or unblocked directly from the interface.

## Technologies Used

- Frontend: HTML, CSS (Bootstrap)
- Backend: Python, Flask
- Machine Learning: Scikit-learn (Random Forest, Label Encoding)
- Real-time Blocking: Windows Firewall rules via script
- Future Scope: TShark, Visual Dashboards, Blockchain Audit Trails

## Results

- Achieved 98.10% detection accuracy on custom datasets.
- Built and deployed `attack_classification_model.pkl` and `label_encoder.pkl`.
- Developed fully functional web interface for upload, classify, and act.
- Blocklist interface for managing false positives and restoring access.

## Installation & Setup

### Prerequisites

- Python 3.x  
- Flask, scikit-learn, pandas  
- Windows OS (for IP blocking)  
- Dataset logs in `.csv` format

### Clone and Run the App

```bash
git clone https://github.com/kishan0818/Cyber_Triage.git
cd Cyber_Triage
pip install -r requirements.txt
.\run_app.bat

```
- Provide Administrative Privileges
- Redirect to http://127.0.0.1:5000 to access the page in local machine

## Contributors
- **Jayakishan B** - [LinkedIn](https://www.linkedin.com/in/jayakishan-balagopal-978613300/) | [GitHub](https://github.com/kishan0818)
- **Jaspreet Singh** - [LinkedIn](https://www.linkedin.com/in/jaspreet-singh-b0366028b/) | [GitHub](https://github.com/Jaspreet51ngh)

## License
This project is licensed under the **CC0 1.0 Universal**.

Feel free to star this repository if you find it useful.



