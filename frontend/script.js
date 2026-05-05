let myChart = null; // Variable to track the chart

function analyzeFile() {
    const fileInput = document.getElementById("fileInput");

    if (!fileInput.files.length) {
        alert("Please upload a CSV file first.");
        return;
    }

    // 1. Display Demo Results
    document.getElementById("status").innerText = "Malicious";
    document.getElementById("status").style.color = "red"; // Added color for impact
    document.getElementById("attackType").innerText = "DoS Attack";
    document.getElementById("severity").innerText = "High";
    document.getElementById("confidence").innerText = "94%";
    document.getElementById("recommendation").innerText = "Block suspicious IP immediately";

    // 2. Update Alert Message
    document.getElementById("alertMessage").innerText =
        "⚠ High Severity Threat Detected: DoS Attack from suspicious traffic!";

    // 3. Trigger the Pie Chart Update
    updateChart();
}

function updateChart() {
    const ctx = document.getElementById("attackChart").getContext("2d");

    // If a chart already exists, destroy it so we can create a fresh one
    if (myChart !== null) {
        myChart.destroy();
    }

    myChart = new Chart(ctx, {
        type: "pie",
        data: {
            labels: ["DoS Attack", "Phishing", "Malware", "Brute Force"],
            datasets: [{
                label: "Detected Threats",
                data: [40, 25, 20, 15],
                backgroundColor: ["red", "yellow", "green", "orange"],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true, // Ensures it stays small
            plugins: {
                legend: {
                    position: "top"
                }
            }
        }
    });
}