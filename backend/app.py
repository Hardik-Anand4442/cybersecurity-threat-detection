from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd

app = Flask(__name__)
CORS(app)

model = joblib.load("model.pkl")
protocol_encoder = joblib.load("protocol_encoder.pkl")
service_encoder = joblib.load("service_encoder.pkl")
flag_encoder = joblib.load("flag_encoder.pkl")

@app.route("/")
def home():
    return "Cybersecurity Threat Detection Backend is running"

def format_result(prediction, confidence):
    if prediction == "normal":
        return {
            "status": "Normal",
            "attack_type": "No Attack",
            "severity": "Low",
            "confidence": confidence,
            "recommendation": "No immediate action required.",
            "alert": "✅ Normal traffic detected. No threat found."
        }

    if prediction == "dos":
        return {
            "status": "Malicious",
            "attack_type": "DoS Attack",
            "severity": "High",
            "confidence": confidence,
            "recommendation": "Monitor traffic and block suspicious IP addresses.",
            "alert": "⚠ High Severity Threat Detected: DoS Attack."
        }

    if prediction == "probe":
        return {
            "status": "Malicious",
            "attack_type": "Reconnaissance / Probe Attack",
            "severity": "Medium",
            "confidence": confidence,
            "recommendation": "Monitor scanning activity and restrict suspicious hosts.",
            "alert": "⚠ Reconnaissance activity detected."
        }

    if prediction == "r2l":
        return {
            "status": "Malicious",
            "attack_type": "Brute Force / Remote-to-Local Attack",
            "severity": "High",
            "confidence": confidence,
            "recommendation": "Review login attempts and strengthen authentication.",
            "alert": "⚠ Possible brute force or unauthorized access attempt."
        }

    if prediction == "u2r":
        return {
            "status": "Malicious",
            "attack_type": "Privilege Escalation Attack",
            "severity": "Critical",
            "confidence": confidence,
            "recommendation": "Investigate affected system immediately.",
            "alert": "🚨 Critical Threat: Privilege escalation detected."
        }

    return {
        "status": "Unknown",
        "attack_type": str(prediction),
        "severity": "Unknown",
        "confidence": confidence,
        "recommendation": "Further analysis required.",
        "alert": "Unknown traffic pattern detected."
    }

def predict_dataframe(df):
    df["protocol_type"] = protocol_encoder.transform(df["protocol_type"])
    df["service"] = service_encoder.transform(df["service"])
    df["flag"] = flag_encoder.transform(df["flag"])

    prediction = model.predict(df)[0]

    confidence = "N/A"
    if hasattr(model, "predict_proba"):
        prob = model.predict_proba(df)[0]
        confidence = str(round(max(prob) * 100, 2)) + "%"

    return format_result(prediction, confidence)

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        df = pd.DataFrame([data])
        return jsonify(predict_dataframe(df))
    except Exception as e:
        return jsonify({"error": str(e)})

@app.route("/predict_csv", methods=["POST"])
def predict_csv():
    try:
        file = request.files["file"]
        df = pd.read_csv(file)

        result = predict_dataframe(df)
        return jsonify(result)

    except Exception as e:
        return jsonify({"error": str(e)})

if __name__ == "__main__":
    app.run(debug=True)