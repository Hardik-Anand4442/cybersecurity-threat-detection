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

@app.route("/ask_cybershield", methods=["POST"])
def ask_cybershield():
    try:
        data = request.json
        question = data.get("question", "").lower()
        context = data.get("context", None)

        aliases = {
            "xxs": "xss",
            "cross site": "xss",
            "cross-site": "xss",
            "bruteforce": "password",
            "brute force": "password",
            "login attack": "password",
            "man in the middle": "mitm",
            "middle attack": "mitm",
            "scan": "scanning",
            "port scan": "scanning",
            "distributed denial": "ddos",
            "denial of service": "dos"
        }

        for wrong, correct in aliases.items():
            if wrong in question:
                question = question.replace(wrong, correct)

        attack_info = {
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "meaning": "XSS is a web attack where malicious scripts are injected into trusted websites.",
                "danger": "It can steal cookies, session tokens, or redirect users to malicious pages.",
                "prevention": "Use input validation, output encoding, Content Security Policy, and sanitize user input."
            },
            "ddos": {
                "name": "Distributed Denial of Service",
                "meaning": "DDoS attacks overload a target using traffic from multiple sources.",
                "danger": "It can make websites, servers, or services unavailable.",
                "prevention": "Use rate limiting, traffic filtering, CDN protection, and DDoS mitigation services."
            },
            "dos": {
                "name": "Denial of Service",
                "meaning": "DoS attacks overload a system from a single or limited source.",
                "danger": "It can exhaust resources and stop legitimate users from accessing services.",
                "prevention": "Use firewall rules, throttling, monitoring, and resource protection."
            },
            "backdoor": {
                "name": "Backdoor Attack",
                "meaning": "A backdoor creates hidden unauthorized access to a system.",
                "danger": "Attackers can bypass normal authentication and control systems secretly.",
                "prevention": "Use malware scanning, patching, access audits, and endpoint monitoring."
            },
            "password": {
                "name": "Password Attack",
                "meaning": "Password attacks try to guess or brute-force login credentials.",
                "danger": "They can lead to account takeover and unauthorized access.",
                "prevention": "Use strong passwords, MFA, account lockout, and login monitoring."
            },
            "injection": {
                "name": "Injection Attack",
                "meaning": "Injection attacks insert malicious commands or payloads into applications.",
                "danger": "They can expose databases, execute commands, or bypass security.",
                "prevention": "Use input validation, parameterized queries, and sanitization."
            },
            "mitm": {
                "name": "Man-in-the-Middle Attack",
                "meaning": "MITM attacks intercept communication between two parties.",
                "danger": "Attackers can steal data or manipulate transmitted information.",
                "prevention": "Use HTTPS, certificate validation, VPNs, and encrypted communication."
            },
            "ransomware": {
                "name": "Ransomware",
                "meaning": "Ransomware encrypts files and demands payment for recovery.",
                "danger": "It can cause data loss, downtime, and financial damage.",
                "prevention": "Use offline backups, endpoint protection, patching, and user awareness."
            },
            "scanning": {
                "name": "Scanning / Reconnaissance",
                "meaning": "Scanning identifies open ports, services, and vulnerabilities.",
                "danger": "It is often the first step before exploitation.",
                "prevention": "Restrict exposed ports, harden firewalls, and monitor repeated scans."
            },
            "normal": {
                "name": "Normal Traffic",
                "meaning": "Normal traffic means legitimate network activity.",
                "danger": "No immediate threat detected.",
                "prevention": "Continue monitoring and maintain security best practices."
            }
        }

        current_attack = None

        if context and "attack_type" in context:
            current_attack = str(context["attack_type"]).lower()

        for key in attack_info:
            if key in question:
                current_attack = key

        if ("this" in question or "detected" in question or "current" in question) and current_attack:
            info = attack_info.get(current_attack)

            if not info:
                return jsonify({
                    "answer": "The current detected attack is not available in my knowledge base yet."
                })

            if "prevent" in question or "avoid" in question or "stop" in question:
                return jsonify({
                    "answer": f"For the current detected threat ({info['name']}), prevention includes: {info['prevention']}"
                })

            if "danger" in question or "risk" in question or "harm" in question:
                return jsonify({
                    "answer": f"The current detected threat ({info['name']}) is dangerous because: {info['danger']}"
                })

            return jsonify({
                "answer": (
                    f"The current detected threat is {info['name']}.\n\n"
                    f"What it is: {info['meaning']}\n\n"
                    f"Why it is dangerous: {info['danger']}\n\n"
                    f"Prevention: {info['prevention']}"
                )
            })

        for key, info in attack_info.items():
            if key in question:
                return jsonify({
                    "answer": (
                        f"{info['name']}\n\n"
                        f"What it is: {info['meaning']}\n\n"
                        f"Why it is dangerous: {info['danger']}\n\n"
                        f"Prevention: {info['prevention']}"
                    )
                })

        if "project" in question or "system" in question or "ids" in question or "use" in question:
            return jsonify({
                "answer": "AI-CYBER SHIELD is a deployable AI-driven intrusion detection prototype. It analyzes network traffic CSV files, detects 10 attack classes, explains threats, provides recommendations, supports adversarial awareness, and assists users through a cybersecurity assistant."
            })

        return jsonify({
            "answer": "I can answer questions about the current detected threat, prevention methods, severity, recommendations, CSV quality, adversarial awareness, autonomous response, and IDS project functionality."
        })

    except Exception as e:
        return jsonify({"error": str(e)})
if __name__ == "__main__":
    app.run(debug=True)