from flask import Flask, request, jsonify
from flask_cors import CORS

import pandas as pd
import joblib
import numpy as np

app = Flask(__name__)
CORS(app)

# Load model files
model = joblib.load("final_rf_model.pkl")

encoders = joblib.load("final_feature_encoders.pkl")

target_encoder = joblib.load("final_target_encoder.pkl")

feature_columns = joblib.load("final_feature_columns.pkl")


@app.route("/")
def home():
    return "AI Cybersecurity Backend Running"


@app.route("/predict_csv", methods=["POST"])
def predict_csv():

    try:
        file = request.files["file"]

        df = pd.read_csv(file)

        # Encode categorical columns
        categorical_cols = ['proto', 'service', 'state']

        for col in categorical_cols:
            if col in df.columns:
                df[col] = encoders[col].transform(df[col].astype(str))

        # Keep required columns only
        df = df[feature_columns]

        # Prediction
        prediction = model.predict(df)[0]

        # Confidence
        probabilities = model.predict_proba(df)[0]

        confidence = round(np.max(probabilities) * 100, 2)

        attack_name = target_encoder.inverse_transform([prediction])[0]

        # Status
        if attack_name.lower() == "normal":
            status = "Normal"
            severity = "Low"
            recommendation = "No immediate action required."

        else:
            status = "Malicious"

            if confidence > 90:
                severity = "High"
            elif confidence > 70:
                severity = "Medium"
            else:
                severity = "Low"

            recommendation = (
                "Investigate suspicious traffic and block malicious source."
            )

        # Top important features
        top_features = [
            "sbytes",
            "smean",
            "sload"
        ]

        return jsonify({

            "status": status,

            "attack_type": attack_name,

            "confidence": f"{confidence}%",

            "severity": severity,

            "recommendation": recommendation,

            "top_features": top_features,

            "alert": (
                f"⚠ Threat Detected: {attack_name}"
                if status == "Malicious"
                else "✅ Network traffic appears safe."
            )
        })

    except Exception as e:

        return jsonify({
            "error": str(e)
        })


if __name__ == "__main__":
    app.run(debug=True)