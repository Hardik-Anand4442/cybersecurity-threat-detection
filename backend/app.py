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

@app.route("/predict", methods=["POST"])
def predict():
    try:
        data = request.json
        df = pd.DataFrame([data])

        df["protocol_type"] = protocol_encoder.transform(df["protocol_type"])
        df["service"] = service_encoder.transform(df["service"])
        df["flag"] = flag_encoder.transform(df["flag"])

        prediction = model.predict(df)[0]

        return jsonify({
            "prediction": prediction
        })

    except Exception as e:
        return jsonify({
            "error": str(e)
        })

if __name__ == "__main__":
    app.run(debug=True)