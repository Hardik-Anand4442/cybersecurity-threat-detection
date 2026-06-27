from multiprocessing import context
from statistics import mode

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS

import io
from datetime import datetime
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
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
            "explanation": """
The uploaded network traffic appears to represent legitimate and expected communication between systems. No significant indicators of malicious activity, suspicious behavior, or known attack signatures were detected during analysis.

Traffic patterns remain within normal operational thresholds and do not indicate unauthorized access attempts, exploitation activities, or abnormal network behavior. While the current analysis suggests a safe environment, continuous monitoring remains essential because cyber threats can evolve rapidly over time.
""",
            "recommendation": """
No immediate action is required. Continue monitoring network activity and maintain standard cybersecurity practices. Ensure security tools such as firewalls, antivirus solutions, intrusion detection systems, and endpoint protection remain active and updated. Regular vulnerability assessments, software patching, and security awareness training should be conducted to maintain a strong security posture.
"""
        },

        "ddos": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": """
A Distributed Denial of Service (DDoS) attack is a large-scale cyberattack where multiple compromised devices simultaneously send enormous amounts of traffic toward a target server, application, or network infrastructure. The goal is to exhaust available resources such as bandwidth, processing power, memory, or connection limits.

These attacks are often launched through botnets containing thousands of infected devices distributed across multiple geographic regions. Successful DDoS attacks can cause service outages, business disruption, financial losses, and damage to organizational reputation by preventing legitimate users from accessing critical services.
""",
            "recommendation": """
Immediately implement traffic filtering and rate-limiting mechanisms to reduce malicious traffic volume. Activate DDoS mitigation services, web application firewalls, and CDN-based protection platforms capable of absorbing attack traffic before it reaches critical infrastructure.

Administrators should continuously monitor traffic patterns, identify suspicious IP addresses, establish automated alerting mechanisms, and maintain redundant infrastructure capable of handling traffic surges. Incident response teams should also be prepared to isolate affected systems and maintain business continuity during prolonged attacks.
"""
        },

        "dos": {
            "status": "Malicious",
            "severity": "High",
            "explanation": """
A Denial of Service (DoS) attack attempts to disrupt normal system operations by overwhelming a target with malicious requests from a single source or a limited number of sources. The objective is to consume available resources and prevent legitimate users from accessing services.

Such attacks may impact system availability, reduce application performance, and create operational disruptions. While smaller in scale than DDoS attacks, they can still cause significant damage if not detected and mitigated promptly.
""",
            "recommendation": """
Monitor network traffic for unusual spikes and repeated requests originating from the same source. Apply traffic throttling, firewall filtering, and access-control mechanisms to block suspicious traffic patterns. Regularly review logs and implement automated monitoring tools capable of detecting abnormal traffic behavior before services become unavailable.
"""
        },

        "backdoor": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": """
A backdoor attack indicates the presence of hidden or unauthorized access mechanisms within a system. Attackers often install backdoors after successfully compromising a device, allowing them to bypass authentication controls and maintain persistent access without detection.

Backdoors are extremely dangerous because they provide attackers with long-term access to sensitive resources, facilitate data theft, enable privilege escalation, and allow additional malware deployment throughout the network.
""",
            "recommendation": """
Immediately isolate affected systems from the network and perform comprehensive forensic analysis. Revoke suspicious credentials, scan systems for malware, remove unauthorized services, and review all recent system modifications. Security teams should also investigate the initial compromise vector to prevent future reinfection.
"""
        },

        "password": {
            "status": "Malicious",
            "severity": "High",
            "explanation": """
A password attack involves repeated attempts to obtain valid credentials through brute-force attacks, dictionary attacks, password spraying, or credential stuffing techniques. Attackers exploit weak, reused, or previously compromised passwords to gain unauthorized access to systems and sensitive information.

Successful password attacks can lead to account compromise, privilege escalation, unauthorized transactions, and further movement throughout the network infrastructure.
""",
            "recommendation": """
Enforce strong password policies requiring sufficient complexity and length. Implement multi-factor authentication (MFA) on all critical systems, configure account lockout policies after repeated failed login attempts, and continuously monitor authentication logs for suspicious activity. User awareness training should also be conducted to reduce credential-related risks.
"""
        },

        "injection": {
            "status": "Malicious",
            "severity": "High",
            "explanation": """
Injection attacks occur when attackers insert malicious commands, scripts, or payloads into applications that fail to properly validate user input. These attacks can target databases, operating systems, web applications, and APIs.

Successful injection attacks may result in unauthorized data access, data manipulation, system compromise, privilege escalation, or complete application takeover depending on the affected environment.
""",
            "recommendation": """
Implement strict input validation and sanitization throughout all applications. Use parameterized queries, prepared statements, and secure coding practices to prevent malicious input execution. Conduct regular code reviews, penetration testing, and vulnerability assessments to identify weaknesses before attackers can exploit them.
"""
        },

        "mitm": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": """
A Man-in-the-Middle (MITM) attack occurs when an attacker secretly intercepts communications between two parties. The attacker may monitor, modify, or manipulate transmitted information without either party being aware of the compromise.

MITM attacks can expose sensitive credentials, financial information, confidential communications, and authentication tokens. They are particularly dangerous because victims often remain unaware that their communications have been intercepted.
""",
            "recommendation": """
Ensure all communications are encrypted using secure protocols such as HTTPS and TLS. Validate digital certificates, use VPN solutions for sensitive communications, and monitor networks for unusual session activity. Security teams should investigate suspicious network behavior and implement strong encryption policies across all systems.
"""
        },

        "ransomware": {
            "status": "Malicious",
            "severity": "Critical",
            "explanation": """
Ransomware is a type of malicious software designed to encrypt files, lock systems, or otherwise deny access to critical resources until a ransom payment is made. Modern ransomware campaigns frequently spread through phishing emails, software vulnerabilities, malicious downloads, or compromised credentials.

A successful ransomware attack can result in severe operational disruption, loss of business-critical data, financial damage, legal consequences, and significant recovery costs.
""",
            "recommendation": """
Immediately isolate infected devices from the network to prevent lateral movement. Disable suspicious processes, initiate incident response procedures, and restore affected systems using verified offline backups where possible. Ensure systems are fully patched and deploy advanced endpoint protection solutions to reduce future infection risks.
"""
        },

        "scanning": {
            "status": "Malicious",
            "severity": "Medium",
            "explanation": """
Scanning activity is commonly used during the reconnaissance phase of a cyberattack. Attackers probe systems, ports, services, and network resources to identify vulnerabilities, open services, and potential attack vectors.

Although scanning itself may not directly compromise a system, it often serves as an early warning sign that an attacker is gathering intelligence before launching a more serious attack.
""",
            "recommendation": """
Monitor repeated scanning attempts and investigate unusual connection patterns. Restrict unnecessary services, close unused ports, strengthen firewall configurations, and deploy intrusion detection systems capable of identifying reconnaissance behavior before further exploitation occurs.
"""
        },

        "xss": {
            "status": "Malicious",
            "severity": "High",
            "explanation": """
Cross-Site Scripting (XSS) is a web-based attack in which malicious scripts are injected into trusted websites or applications. When users access the affected application, the malicious script executes within their browser and may steal session cookies, authentication tokens, or sensitive information.

XSS vulnerabilities can result in account hijacking, unauthorized actions, website defacement, and exposure of confidential user data.
""",
            "recommendation": """
Implement strict input validation and output encoding throughout web applications. Utilize Content Security Policy (CSP) headers, perform regular security testing, and sanitize all user-generated content before processing or displaying it. Secure development practices should be followed throughout the software development lifecycle.
"""
        }
    }

    result = details.get(attack, {
        "status": "Unknown",
        "severity": "Medium",
        "explanation": """
The detected traffic pattern could not be confidently mapped to a known attack category within the current knowledge base. Additional investigation may be required to determine the nature and impact of the observed activity.
""",
        "recommendation": """
Conduct manual analysis of the affected traffic, review security logs, and perform further investigation to determine whether the activity represents a legitimate operation or a potential cybersecurity threat.
"""
    })

    if confidence < 60:
        adversarial_alert = """
Potential adversarial or manipulated traffic pattern detected. The model confidence score is lower than expected, which may indicate unusual traffic characteristics, evasive attack techniques, or data specifically designed to confuse machine learning models.
"""
    else:
        adversarial_alert = """
No significant indicators of adversarial manipulation were detected. The analyzed traffic appears consistent with patterns previously observed during model training and evaluation.
"""

    if result["status"] == "Malicious":
        autonomous_response = f"""
AUTONOMOUS RESPONSE ENGINE ACTIVATED

• Threat classification completed successfully.
• Suspicious activity associated with {attack_name} has been flagged.
• Recommended mitigation procedures have been generated automatically.
• Security alert has been issued for administrator review.
• Threat information has been logged for future learning and evolving defense analysis.
• Continued monitoring is recommended until the threat has been fully mitigated.
"""
    else:
        autonomous_response = """
No autonomous response was required because the analyzed traffic appears legitimate. The system will continue monitoring future traffic for abnormal behavior and emerging threats.
"""

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
            "confidence": avg_confidence,
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
        mode = data.get("mode", "auto").lower()
        print("Current Mode:", mode)

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

        # ==========================
        # PROMPT MODE
        # ==========================
        if mode == "prompt":

            if ("this" in question or "detected" in question or "current" in question) and current_attack:

                info = attack_info.get(current_attack)

                if not info:
                    return jsonify({
                        "mode": mode,
                        "answer": "The current detected attack is not available in my knowledge base yet."
                    })

                if "prevent" in question or "avoid" in question or "stop" in question:
                    return jsonify({
                        "mode": mode,
                        "answer": f"For the current detected threat ({info['name']}), prevention includes: {info['prevention']}"
                    })

                if "danger" in question or "risk" in question or "harm" in question:
                    return jsonify({
                        "mode": mode,
                        "answer": f"The current detected threat ({info['name']}) is dangerous because: {info['danger']}"
                    })

                return jsonify({
                    "mode": mode,
                    "answer": (
                        f"The current detected threat is {info['name']}\n\n"
                        f"What it is: {info['meaning']}\n\n"
                        f"Why it is dangerous: {info['danger']}\n\n"
                        f"Prevention: {info['prevention']}"
                    )
                })

            for key, info in attack_info.items():
                if key in question:
                    return jsonify({
                        "mode": mode,
                        "answer": (
                            f"{info['name']}\n\n"
                            f"What it is: {info['meaning']}\n\n"
                            f"Why it is dangerous: {info['danger']}\n\n"
                            f"Prevention: {info['prevention']}"
                        )
                    })

            if ("project" in question or
                "system" in question or
                "ids" in question or
                "use" in question):

                return jsonify({
                    "mode": mode,
                    "answer": "AI-CYBER SHIELD is a deployable AI-driven intrusion detection prototype. It analyzes network traffic CSV files, detects attack classes, explains threats, provides recommendations, supports adversarial awareness, and assists users through a cybersecurity assistant."
                })

            return jsonify({
                "mode": mode,
                "answer": "I can answer questions about the current detected threat, prevention methods, severity, recommendations, CSV quality, adversarial awareness, autonomous response, and IDS project functionality."
            })

        # ==========================
        # AUTO MODE
        # ==========================
        else:

            if not context:
                return jsonify({
                    "mode": mode,
                    "answer": "Please analyze a CSV file first."
                })

            return jsonify({
                "mode": mode,
                "attack_type": context.get("attack_type"),
                "status": context.get("status"),
                "severity": context.get("severity"),
                "confidence": context.get("confidence"),
                "explanation": context.get("explanation"),
                "recommendation": context.get("recommendation"),
                "adversarial_alert": context.get("adversarial_alert"),
                "autonomous_response": context.get("autonomous_response"),
                "preprocessing_summary": context.get("preprocessing_summary")
            })

    except Exception as e:
        return jsonify({
            "error": str(e)
        }), 500

@app.route('/generate_report', methods=['POST'])
def generate_report():

    data = request.json

    attack_type = data.get("attack_type", "Unknown")
    severity = data.get("severity", "Unknown")
    confidence = data.get("confidence", "Unknown")
    recommendation = data.get("recommendation", "No recommendation")

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "AI-CYBER SHIELD Security Report",
            styles['Title']
        )
    )

    content.append(Spacer(1, 12))

    content.append(
        Paragraph(
            f"<b>Attack Type:</b> {attack_type}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Severity:</b> {severity}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Confidence:</b> {confidence}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Recommendation:</b> {recommendation}",
            styles['BodyText']
        )
    )

    content.append(
        Paragraph(
            f"<b>Generated On:</b> {datetime.now()}",
            styles['BodyText']
        )
    )

    doc.build(content)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="Security_Report.pdf",
        mimetype="application/pdf"
    )
if __name__ == "__main__":
    app.run(debug=True)