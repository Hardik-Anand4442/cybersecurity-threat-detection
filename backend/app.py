from flask import Flask, request, jsonify
from flask_cors import CORS

import pandas as pd
import joblib
import numpy as np

app = Flask(__name__)
CORS(app)

# Load final TON_IoT model files
model = joblib.load("FINAL_model.pkl")
target_encoder = joblib.load("FINAL_target_encoder.pkl")
feature_columns = joblib.load("FINAL_feature_columns.pkl")
classes = joblib.load("FINAL_classes.pkl")
feature_encoders = joblib.load("FINAL_feature_encoders.pkl")


@app.route("/")
def home():
    return "AI-CYBER SHIELD Backend Running"


def get_attack_details(attack_name, confidence):
    attack = attack_name.lower()

    details = {
        "normal": {
            "status": "Normal",
            "severity": "Low",
            "explanation": "The uploaded traffic appears to be legitimate network activity.",
            "recommendation": "No immediate action required. Continue monitoring the network."
        },
        "ddos": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": "A Distributed Denial of Service attack attempts to overwhelm a target using traffic from multiple sources.",
            "recommendation": "Rate-limit incoming requests, block suspicious IP ranges, and activate DDoS mitigation controls."
        },
        "dos": {
            "status": "Malicious",
            "severity": "High",
            "explanation": "A Denial of Service attack attempts to disrupt services by overwhelming system resources.",
            "recommendation": "Monitor traffic spikes, block malicious sources, and apply request throttling."
        },
        "backdoor": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": "A backdoor attack indicates unauthorized hidden access to a system.",
            "recommendation": "Isolate the affected host, revoke suspicious access, and perform malware scanning."
        },
        "password": {
            "status": "Malicious",
            "severity": "High",
            "explanation": "A password attack involves repeated attempts to guess or brute-force login credentials.",
            "recommendation": "Enforce strong passwords, enable multi-factor authentication, and block repeated login attempts."
        },
        "injection": {
            "status": "Malicious",
            "severity": "High",
            "explanation": "Injection attacks attempt to insert malicious commands or payloads into applications or systems.",
            "recommendation": "Validate inputs, sanitize user data, and monitor abnormal request patterns."
        },
        "mitm": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": "A Man-in-the-Middle attack attempts to intercept or manipulate communication between two parties.",
            "recommendation": "Use encrypted communication, validate certificates, and monitor suspicious network sessions."
        },
        "ransomware": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": "Ransomware attempts to encrypt or lock data and demand payment for recovery.",
            "recommendation": "Isolate affected devices, disable suspicious processes, restore backups, and notify security teams."
        },
        "scanning": {
            "status": "Malicious",
            "severity": "Medium",
            "explanation": "Scanning activity indicates reconnaissance where an attacker probes systems, ports, or services.",
            "recommendation": "Monitor repeated scan attempts, restrict exposed services, and block suspicious scanners."
        },
        "xss": {
            "status": "Malicious",
            "severity": "High",
            "explanation": "Cross-Site Scripting attempts to inject malicious scripts into web applications.",
            "recommendation": "Apply input validation, output encoding, and secure web application filtering."
        }
    }

    result = details.get(attack, {
        "status": "Unknown",
        "severity": "Medium",
        "explanation": "The traffic pattern could not be mapped to a known category.",
        "recommendation": "Manual review is recommended."
    })

    if confidence < 60:
        adversarial_alert = "Potential adversarial or manipulated traffic pattern detected due to low model confidence."
    else:
        adversarial_alert = "No adversarial manipulation indicators detected."

    if result["status"] == "Malicious":
        autonomous_response = f"Suggested action: isolate affected traffic and apply mitigation for {attack_name}."
    else:
        autonomous_response = "No autonomous response required."

    return result, adversarial_alert, autonomous_response


@app.route("/predict_csv", methods=["POST"])
def predict_csv():
    try:
        file = request.files["file"]
        df = pd.read_csv(file)

        original_rows = len(df)

        # Basic preprocessing
        df.columns = df.columns.str.strip()
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.dropna()

        processed_rows = len(df)
        removed_rows = original_rows - processed_rows

        # Check required columns
        missing_cols = [col for col in feature_columns if col not in df.columns]

        if missing_cols:
            return jsonify({
                "error": "Uploaded CSV does not match required TON_IoT feature format.",
                "missing_columns": missing_cols[:10],
                "message": "Please upload a TON_IoT-compatible CSV sample."
            })

        # Keep only training features
        df = df[feature_columns]

        # Encode categorical columns using SAME encoders from training
        for col in feature_encoders:
            if col in df.columns:
                df[col] = df[col].astype(str)

                encoder = feature_encoders[col]
                known_values = set(encoder.classes_)

                df[col] = df[col].apply(
                    lambda x: x if x in known_values else encoder.classes_[0]
                )

                df[col] = encoder.transform(df[col])

        # Prediction
        predictions = model.predict(df)
        probabilities = model.predict_proba(df)

        # Main prediction = most frequent prediction in uploaded CSV
        main_prediction = pd.Series(predictions).mode()[0]
        attack_name = target_encoder.inverse_transform([main_prediction])[0]

        avg_confidence = round(np.max(probabilities, axis=1).mean() * 100, 2)

        details, adversarial_alert, autonomous_response = get_attack_details(
            attack_name,
            avg_confidence
        )

        decoded_predictions = target_encoder.inverse_transform(predictions)
        distribution = pd.Series(decoded_predictions).value_counts().to_dict()

        return jsonify({
            "status": details["status"],
            "attack_type": attack_name,
            "severity": details["severity"],
            "confidence": f"{avg_confidence}%",
            "explanation": details["explanation"],
            "recommendation": details["recommendation"],
            "alert": (
                f"⚠ Threat Detected: {attack_name}"
                if details["status"] == "Malicious"
                else "✅ Network traffic appears safe."
            ),
            "adversarial_alert": adversarial_alert,
            "autonomous_response": autonomous_response,
            "preprocessing_summary": {
                "uploaded_rows": original_rows,
                "processed_rows": processed_rows,
                "removed_rows": removed_rows
            },
            "attack_distribution": distribution
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        })


if __name__ == "__main__":
    app.run(debug=True)