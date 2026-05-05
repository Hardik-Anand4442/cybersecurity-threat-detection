async function predict() {
    const data = {
        duration: parseInt(document.getElementById("duration").value),
        protocol_type: document.getElementById("protocol_type").value,
        service: document.getElementById("service").value,
        flag: document.getElementById("flag").value,
        src_bytes: parseInt(document.getElementById("src_bytes").value),
        dst_bytes: parseInt(document.getElementById("dst_bytes").value),

        // fill remaining fields with default values (IMPORTANT)
        land: 0,
        wrong_fragment: 0,
        urgent: 0,
        hot: 0,
        num_failed_logins: 0,
        logged_in: 1,
        num_compromised: 0,
        root_shell: 0,
        su_attempted: 0,
        num_root: 0,
        num_file_creations: 0,
        num_shells: 0,
        num_access_files: 0,
        num_outbound_cmds: 0,
        is_host_login: 0,
        is_guest_login: 0,
        count: 1,
        srv_count: 1,
        serror_rate: 0,
        srv_serror_rate: 0,
        rerror_rate: 0,
        srv_rerror_rate: 0,
        same_srv_rate: 1,
        diff_srv_rate: 0,
        srv_diff_host_rate: 0,
        dst_host_count: 1,
        dst_host_srv_count: 1,
        dst_host_same_srv_rate: 1,
        dst_host_diff_srv_rate: 0,
        dst_host_same_src_port_rate: 0,
        dst_host_srv_diff_host_rate: 0,
        dst_host_serror_rate: 0,
        dst_host_srv_serror_rate: 0,
        dst_host_rerror_rate: 0,
        dst_host_srv_rerror_rate: 0
    };

    try {
        const response = await fetch("http://127.0.0.1:5000/predict", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        document.getElementById("result").innerText =
            "Prediction: " + result.prediction;

    } catch (error) {
        document.getElementById("result").innerText =
            "Error connecting to backend";
    }
}