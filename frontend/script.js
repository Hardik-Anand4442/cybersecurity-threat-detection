function analyzeFile() {
    const fileInput = document.getElementById("fileInput");

    if (!fileInput.files.length) {
        alert("Please upload a CSV file first.");
        return;
    }

    // Demo Result
    document.getElementById("status").innerText = "Malicious";
    document.getElementById("attackType").innerText = "DoS Attack";
    document.getElementById("severity").innerText = "High";
    document.getElementById("confidence").innerText = "94%";
    document.getElementById("recommendation").innerText =
        "Block suspicious IP immediately";

    document.getElementById("alertMessage").innerText =
        "⚠ High Severity Threat Detected: DoS Attack from suspicious traffic!";
}

// Pie Chart for Attack Types
const ctx = document.getElementById("attackChart").getContext("2d");

new Chart(ctx, {
    type: "pie",
    data: {
        labels: [
            "DoS Attack",
            "Phishing",
            "Malware",
            "Brute Force"
        ],
        datasets: [{
            label: "Detected Threats",
            data: [40, 25, 20, 15],
            backgroundColor: [
                "red",      // High severity
                "yellow",   // Medium severity
                "green",    // Low severity
                "orange"    // Additional threat
            ],
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        plugins: {
            legend: {
                position: "top"
            }
        }
    }
});