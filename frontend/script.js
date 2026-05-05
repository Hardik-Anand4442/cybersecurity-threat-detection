async function analyzeFile() {
    alert("New script is running");
    const fileInput = document.getElementById("fileInput");

    if (!fileInput.files.length) {
        alert("Please upload a CSV file first.");
        return;
    }

    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    try {
        const response = await fetch("http://127.0.0.1:5000/predict_csv", {
            method: "POST",
            body: formData
        });

        const result = await response.json();

        if (result.error) {
            alert(result.error);
            return;
        }

        document.getElementById("status").innerText = result.status;
        document.getElementById("attackType").innerText = result.attack_type;
        document.getElementById("severity").innerText = result.severity;
        document.getElementById("confidence").innerText = result.confidence;
        document.getElementById("recommendation").innerText = result.recommendation;
        document.getElementById("alertMessage").innerText = result.alert;

    } catch (error) {
        alert("Error connecting to backend.");
    }
}