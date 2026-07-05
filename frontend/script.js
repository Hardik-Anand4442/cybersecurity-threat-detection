/**
 * AegisThreat AI - Cybersecurity Threat Detection System Controller
 */
const threatSound = new Audio("Old tv beep - QuickSounds.com.mp3");
threatSound.volume = 0.6;
const threatTableBody = document.getElementById("historyBody");
const stateEmpty = document.getElementById('stateEmpty');
const stateScanning = document.getElementById('stateScanning');
const stateResults = document.getElementById('stateResults');
document.addEventListener('DOMContentLoaded', () => {
    // 1. Live Utility Clock Systems
    const liveTimeEl = document.getElementById('liveTime');
    function updateLiveTime() {
        const now = new Date();
        const timeString = now.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
        if (liveTimeEl) liveTimeEl.textContent = timeString;
    }
    setInterval(updateLiveTime, 1000);
    updateLiveTime();

    // 2. Modals & Top Navigation Controls
    const adminPanelBtn = document.getElementById('adminPanelBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    const adminModal = document.getElementById('adminModal');
    const closeAdminBtn = document.getElementById('closeAdminBtn');
    const lockScreen = document.getElementById('lockScreen');
    const passcodeInput = document.getElementById('passcodeInput');
    const unlockBtn = document.getElementById('unlockBtn');
    const apiUrlInput = document.getElementById('apiUrlInput');
    const resetUrlBtn = document.getElementById('resetUrlBtn');
    const mockModeSwitch = document.getElementById('mockModeSwitch');

    // Admin Settings Modal Bindings
    if (adminPanelBtn && adminModal) {
        adminPanelBtn.addEventListener('click', (e) => {
            e.preventDefault();
            adminModal.style.display = 'flex';
        });
    }

    if (closeAdminBtn && adminModal) {
        closeAdminBtn.addEventListener('click', () => {
            adminModal.style.display = 'none';
        });
    }

    window.addEventListener('click', (e) => {
        if (e.target === adminModal) {
            adminModal.style.display = 'none';
        }
    });

    const DEFAULT_API_URL = 'http://127.0.0.1:5000/predict_csv';
    if (resetUrlBtn && apiUrlInput) {
        resetUrlBtn.addEventListener('click', () => {
            apiUrlInput.value = DEFAULT_API_URL;
            showTerminalLog('Endpoint URL reset to default configuration');
        });
    }

    // Logout & Authorization Key Overlay
    if (logoutBtn && lockScreen) {
        logoutBtn.addEventListener('click', (e) => {
            e.preventDefault();
            lockScreen.style.display = 'flex';
            if (passcodeInput) {
                passcodeInput.value = '';
                passcodeInput.focus();
            }
        });
    }

    function checkPasscode() {
        if (!passcodeInput) return;
        const code = passcodeInput.value.trim();
        if (code === '1337') {
            lockScreen.style.display = 'none';
            showTerminalLog('Security node unlocked. Session authorized.');
        } else {
            passcodeInput.style.animation = 'shake 0.3s';
            passcodeInput.classList.add('error-pulse');
            setTimeout(() => {
                passcodeInput.style.animation = '';
                passcodeInput.classList.remove('error-pulse');
            }, 300);
            alert('Security Failure: Invalid passcode authorization key.');
        }
    }

    if (unlockBtn) {
        unlockBtn.addEventListener('click', checkPasscode);
    }
    if (passcodeInput) {
        passcodeInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') checkPasscode();
        });
    }

    // 3. File Ingestion Variables & Handlers
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('fileInput');
    const fileNameText = document.getElementById('fileNameText');
    const analyzeBtn = document.getElementById('analyzeBtn');

    let activeFile = null;
    let scanResults = [];
    let latestThreatContext = null;

    // Drag-and-drop Events
    const preventDefaults = (e) => {
        e.preventDefault();
        e.stopPropagation();
    };

    if (dropZone) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('dragover');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('dragover');
            }, false);
        });

        dropZone.addEventListener('drop', (e) => {
            const dt = e.dataTransfer;
            const files = dt.files;
            handleFiles(files);
        });
    }

    if (fileInput) {
        fileInput.addEventListener('change', (e) => {
            handleFiles(e.target.files);
        });
    }

    function handleFiles(files) {
        if (files.length === 0) return;
        const file = files[0];
        
        // CSV Validate
        if (!file.name.toLowerCase().endsWith('.csv')) {
            showTerminalLog('Security Reject: Only CSV format allowed.', 'danger');
            alert('File Format Error: Ingestion stream strictly supports CSV tables.');
            return;
        }

        activeFile = file;
        if (fileNameText) {
            fileNameText.textContent = file.name;
        }
        if (analyzeBtn) {
            analyzeBtn.removeAttribute('disabled');
        }
        showTerminalLog(`Ingested traffic file: ${file.name}`);
    }

    // 4. Ingestion Process & State Viewports

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async () => {
            if (!activeFile) return;
            resetChat();
            setDashboardState('scanning');
            try {
                if (mockModeSwitch && mockModeSwitch.checked) {
                    await runMockSimulation(activeFile);
                } else {
                    await runLiveAnalysis(activeFile);
                }
            } catch (err) {
                console.error(err);
                showTerminalLog(`Network Fault: ${err.message}`, 'danger');
                alert(`API Connection Failed: ${err.message}`);
                setDashboardState('empty');
            }
        });
    }

    function setDashboardState(state) {
        if (!stateEmpty || !stateScanning || !stateResults) return;

        stateEmpty.style.display = 'none';
        stateScanning.style.display = 'none';
        stateResults.style.display = 'none';

        if (state === 'empty') {
            stateEmpty.style.display = 'flex';
        } else if (state === 'scanning') {
            stateScanning.style.display = 'flex';
        } else if (state === 'results') {
            stateResults.style.display = 'flex';
        }
    }

    // Helper: Progress visual loader
    function simulateProgress(durationMs) {
        return new Promise((resolve) => {
            let current = 0;
            const stepTime = Math.max(durationMs / 100, 10);
            const statusMessages = [
                'Decrypting CSV packets...',
                'Sanitizing log boundaries...',
                'Forwarding vector logs to prediction node...',
                'Evaluating confidence indices...',
                'Parsing severity labels...',
                'Compiling remediation procedures...'
            ];

            const interval = setInterval(() => {
                current += 1 + Math.floor(Math.random() * 3);
                if (current >= 100) {
                    current = 100;
                    clearInterval(interval);
                    resolve();
                }
                
                if (scanPercent) scanPercent.textContent = `${current.toString().padStart(2, '0')}%`;
                if (scanProgressBar) scanProgressBar.style.width = `${current}%`;
                
                if (scanStatusMsg) {
                    const msgIndex = Math.min(Math.floor((current / 100) * statusMessages.length), statusMessages.length - 1);
                    scanStatusMsg.textContent = statusMessages[msgIndex];
                }
            }, stepTime);
        });
    }

    // Terminal mock logs
    function showTerminalLog(message, type = 'info') {
        console.log(`[${type.toUpperCase()}] ${message}`);
        const term = document.querySelector('.terminal-mock');
        if (term) {
            const time = new Date().toLocaleTimeString();
            term.innerHTML += `<br><span class="term-prompt">&gt;</span> [${time}] ${message}`;
            term.scrollTop = term.scrollHeight;
        }
    }

    // 5. Ingestion Mock Simulation
    async function runMockSimulation(file) {
        const reader = new FileReader();
        const fileContentPromise = new Promise((resolve) => {
            reader.onload = (e) => resolve(e.target.result);
            reader.readAsText(file);
        });

        const csvText = await fileContentPromise;
        const lines = csvText.split('\n').map(l => l.trim()).filter(l => l.length > 0);
        const recordCount = Math.max(lines.length - 1, 1);

        // Run loader
        const progressPromise = simulateProgress(Math.min(1000 + recordCount * 15, 3000));

        // Mock parameters matching second screenshot and typical files
        const mockThreats = [
            { type: 'Exploits', sev: 'low', reco: 'Investigate suspicious traffic and block malicious source.' },
            { type: 'DDoS Attack', sev: 'critical', reco: 'Initiate rate-limiting rules, verify Cloudflare filters, and drop anomalous UDP/TCP streams.' },
            { type: 'Malware', sev: 'high', reco: 'Isolate affected host nodes from LAN subnet, trigger file integrity hashes, and clean registry registries.' },
            { type: 'Phishing', sev: 'medium', reco: 'Flag incoming messages, block domain names, and reset target client user credentials.' },
            { type: 'Brute Force', sev: 'high', reco: 'Configure IP lockouts, revoke compromised keys, and require multi-factor authorization tokens.' }
        ];

        const mockStatuses = ['Malicious', 'Suspicious', 'Clean'];
        const simulatedList = [];

        for (let i = 1; i <= recordCount; i++) {
            // Randomly pick a threat profile, or safe profile
            const isThreat = Math.random() > 0.4;
            if (isThreat) {
                const threat = mockThreats[Math.floor(Math.random() * mockThreats.length)];
                const confidence = parseFloat((35 + Math.random() * 63.8).toFixed(2));
                const status = confidence > 70 ? 'Malicious' : 'Suspicious';
                
                simulatedList.push({
                    status: status,
                    attack_type: threat.type,
                    severity: threat.sev,
                    confidence: confidence,
                    recommendation: threat.reco,
                    alert: `Threat Detected: ${threat.type}`
                });
            } else {
                simulatedList.push({
                    status: 'Clean',
                    attack_type: 'Safe Traffic',
                    severity: 'low',
                    confidence: parseFloat((85 + Math.random() * 14.5).toFixed(2)),
                    recommendation: 'No mitigation required. Clean network footprint.',
                    alert: null
                });
            }
        }

        await progressPromise;

        scanResults = simulatedList;
        renderDashboardResults(scanResults);
        setDashboardState('results');
        showTerminalLog(`Generated ${scanResults.length} simulated detections.`, 'success');
    }

    // 6. Live API Analysis Fetch
    async function runLiveAnalysis(file) {
        const url = (apiUrlInput && apiUrlInput.value.trim()) || DEFAULT_API_URL;
        showTerminalLog(`Connecting to: ${url}`);

        const progressPromise = simulateProgress(2500);

        const formData = new FormData();
        formData.append('file', file);

        let response;
        try {
            response = await fetch(url, {
                method: 'POST',
                body: formData
            });
        } catch (err) {
            throw new Error(`Endpoint connection refused. Check server status or CORS configurations. Trace: ${err.message}`);
        }

        if (!response.ok) {
            throw new Error(`API Gateway returned HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();
        await progressPromise;

        // STEP 1: normalize single backend response
        const normalized = normalizeData(data);

        // STEP 2: FORCE ARRAY (IMPORTANT)
        scanResults = [normalized];

        // DEBUG
        console.log("API RESPONSE (FIXED):", scanResults[0]);
        renderDashboardResults(scanResults);
        setDashboardState('results');
        showTerminalLog(`Ingested ${scanResults.length} live records.`, 'success');
    }

    function normalizeData(item) {
    if (!item) return {};

    return {
        status: (item.status || 'Malicious').toString(),
        attack_type: (item.attack_type || 'Unknown').toString(),
        severity: (item.severity || 'low').toString().toLowerCase(),

        confidence: Number(item.confidence ?? 0),

        recommendation: item.recommendation || 'Investigate suspicious traffic.',
        alert: item.alert || `Threat Detected: ${item.attack_type || 'Unknown'}`,

        explanation: item.explanation || '',
        adversarial_alert: item.adversarial_alert || '',
        autonomous_response: item.autonomous_response || '',

        preprocessing_summary: item.preprocessing_summary || null,
        attack_distribution: item.attack_distribution || null
    };
}
        const threatStatus = document.getElementById("threatStatus");
        const threatAttackType = document.getElementById("threatAttackType");
        const threatSeverity = document.getElementById("threatSeverity");
        const threatConfidence = document.getElementById("threatConfidence");
        const threatRecommendation = document.getElementById("threatRecommendation");
        const recentAlertMsg = document.getElementById("recentAlertMsg");
        const recentAlertCard = document.getElementById("recentAlertCard");
    
        function updateAnalysisUI(row) {
            loadAnalysisResultCard(row);
            if (selectedMode === "auto") {
            generateAutoCyberShieldSummary(row);
        }
        }

        function renderDashboardResults(results) {
        // Render logs registry
            if (!Array.isArray(results)) {
            results = [results];
}
            console.log("renderDashboardResults()");
            console.table(results);
        if (threatTableBody) {
            threatTableBody.querySelectorAll('tr').forEach(r => r.classList.remove('active-row'));
            threatTableBody.innerHTML = '';
            console.table(results);
            results.forEach((row, idx) => {
                const tr = document.createElement('tr');
                tr.dataset.index = idx;
                const severity = (row.severity || '').toString().toLowerCase();
                let sevClass = 'medium';
                const sev = (row.severity || '').toLowerCase();

                if (sev.includes('critical')) sevClass = 'critical';
                else if (sev.includes('high')) sevClass = 'high';
                else if (sev.includes('low')) sevClass = 'low';
                else if (sev.includes('info')) sevClass = 'info';
                else sevClass = 'medium';
                let statusClass = 'neutral';
                const lowerStatus = (row.status || '').toString().toLowerCase();
                if (lowerStatus === 'clean' || lowerStatus === 'cleared') {
                    statusClass = 'clean';
                } else if (lowerStatus === 'malicious' || lowerStatus === 'threat' || lowerStatus === 'suspicious') {
                    statusClass = 'threat';
                }

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color: var(--neon-cyan);">#${(idx + 1).toString().padStart(3, '0')}</td>
                    <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(row.attack_type)}</td>
                    <td><span class="table-pill ${sevClass}">${row.severity.toUpperCase()}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${Number(row.confidence || 0).toFixed(2)}%</td>
                    <td><span class="table-status ${statusClass}">${escapeHtml(row.status)}</span></td>
                    <td class="table-cell-reco" title="${escapeHtml(row.recommendation)}">${escapeHtml(row.recommendation)}</td>
                `;

                tr.addEventListener('click', () => {
                    updateAnalysisUI(row);
                });

                threatTableBody.appendChild(tr);
            });
        }

        // Draw distribution pie chart
        renderDistributionChart(results);

        // Highlight first item
        if (results.length > 0 && threatTableBody) {
            const firstRow = threatTableBody.querySelector('tr');
            if (firstRow) firstRow.click();
        }
    }

    function loadAnalysisResultCard(row) {
        // Populate Analysis Result card (Screenshot 2 specifications)
        console.log("Clicked Row");
        console.log(row);
        if (threatStatus) {
    threatStatus.textContent = `${row.status} (${row.attack_type})`;
    threatStatus.className = "val status-val";

    const status = row.status.toLowerCase();

    if (status === "malicious") {
        threatStatus.classList.add("malicious");
    }
    else if (status === "suspicious") {
        threatStatus.classList.add("suspicious");
    }
    else {
        threatStatus.classList.add("clean");
    }
}
       if (threatAttackType) {

    if (
        row.attack_type === "Multiple Attacks" &&
        row.attack_distribution
    ) {

        let html = "<strong>Multiple Attacks Detected</strong><br>";

        for (const [attack, count] of Object.entries(row.attack_distribution)) {

            if (attack.toLowerCase() !== "normal") {
                html += `<br>• ${attack} (${count})`;
            }

        }

        threatAttackType.innerHTML = html;

    } else {

        threatAttackType.textContent = row.attack_type;

    }

}
        if (threatSeverity) {
            // Capitalize severity word nicely
            const sev = (row.severity || 'low').toString();
            threatSeverity.textContent = row.severity.charAt(0).toUpperCase() + row.severity.slice(1);
        }
        if (threatConfidence) threatConfidence.textContent = `${Number(row.confidence || 0).toFixed(2)}%`;
        if (threatRecommendation) threatRecommendation.textContent = row.recommendation;

        // Populate Recent Alert card (Screenshot 2 specifications)
        if (recentAlertCard) {
            recentAlertCard.classList.remove('malicious-alert');
        }
        if (recentAlertMsg) {
        const status = row.status?.toLowerCase();

        const isThreat =
            status === "malicious" ||
            status === "suspicious" ||
            status === "threat";

        if (isThreat) {
            recentAlertMsg.textContent = `⚠ Threat Detected: ${row.attack_type}`;
            recentAlertCard.classList.add('malicious-alert');
        } else {
            recentAlertMsg.textContent = `✔ Safe Log Stream: Clean Broadcast`;
        }
    }
    triggerThreatPopup(row);
    }

    // 8. Dynamic HTML5 Canvas Pie/Doughnut Chart drawing
    const canvas = document.getElementById('threatDistributionChart');
    const legendEl = document.getElementById('chartLegend');
    
    function triggerThreatPopup(row) {
        const popup = document.getElementById("threatPopup");
        const popupText = document.getElementById("popupText");

        if (!popup) return;

        const status = (row.status || "").toLowerCase();

        if (status === "malicious" || status === "suspicious") {

            popupText.textContent = `${row.attack_type} detected (${row.severity})`;

            popup.classList.remove("hidden");
            popup.classList.add("blink");

            // 🔊 PLAY SOUND
            try {
                threatSound.currentTime = 0;
                threatSound.play();
            } catch (e) {
                console.log("Audio blocked until user interaction");
            }

            // auto hide
            setTimeout(() => {
                popup.classList.add("hidden");
                popup.classList.remove("blink");
            }, 4000);
        }
    }
    function renderDistributionChart(data) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Aggregate counts by attack type
        const counts = {};
        scanResults.forEach(item => {
            const type = item.attack_type;
            counts[type] = (counts[type] || 0) + 1;
        });

        const total = scanResults.length || 1;
        const types = Object.keys(counts);

        // Theme palette color mappings
        const colorPalette = {
            'Exploits': '#ff5500',             // Amber/orange
            'DDoS Attack': '#ff0055',          // Critical Red
            'Malware': '#bd00ff',              // Purple
            'Phishing': '#ffaa00',             // Yellow
            'Brute Force': '#ff0000',          // High Red
            'Safe Traffic': '#39ff14',         // Bright green
            'Safe Network Broadcast': '#39ff14',
            'Brute Force SSH Attack': '#ff5500'
        };

        const defaultColors = ['#00f0ff', '#bd00ff', '#ffaa00', '#ff0055', '#39ff14', '#00b8ff', '#94a3b8'];

        // Assign colors and build slices data structure
        const slices = types.map((type, idx) => {
            const count = counts[type];
            const color = colorPalette[type] || defaultColors[idx % defaultColors.length];
            return {
                label: type,
                count: count,
                percent: parseFloat(((count / total) * 100).toFixed(1)),
                color: color
            };
        });

        // Clear canvas
        ctx.clearRect(0, 0, canvas.width, canvas.height);

        // Draw Doughnut
        const centerX = canvas.width / 2;
        const centerY = canvas.height / 2;
        const radius = Math.min(centerX, centerY) - 10;
        const innerRadius = radius * 0.55; // doughnut design

        let startAngle = -Math.PI / 2; // start from top center

        slices.forEach(slice => {
            const sliceAngle = (slice.count / total) * (2 * Math.PI);
            
            // Draw sector path
            ctx.beginPath();
            ctx.arc(centerX, centerY, radius, startAngle, startAngle + sliceAngle);
            ctx.arc(centerX, centerY, innerRadius, startAngle + sliceAngle, startAngle, true);
            ctx.closePath();

            // Fill styling
            ctx.fillStyle = slice.color;
            ctx.fill();

            // Overlay stroke border to separate segments cleanly
            ctx.strokeStyle = '#04060b';
            ctx.lineWidth = 2.5;
            ctx.stroke();

            // Optional glow effect stroke
            ctx.shadowColor = slice.color;
            ctx.shadowBlur = 4;
            ctx.strokeStyle = 'rgba(255,255,255,0.05)';
            ctx.lineWidth = 1;
            ctx.stroke();
            
            // Reset shadows
            ctx.shadowBlur = 0;

            startAngle += sliceAngle;
        });

        // Draw dynamic labels in the center hole
        ctx.beginPath();
        ctx.arc(centerX, centerY, innerRadius - 2, 0, 2 * Math.PI);
        ctx.fillStyle = '#060a14'; // center base match
        ctx.fill();
        ctx.strokeStyle = 'rgba(0, 240, 255, 0.08)';
        ctx.stroke();

        ctx.fillStyle = '#f1f5f9';
        ctx.font = 'bold 12px "Share Tech Mono"';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText(`TOTAL: ${total}`, centerX, centerY);

        // Build legend list
        if (legendEl) {
            legendEl.innerHTML = '';
            slices.forEach(slice => {
                const li = document.createElement('div');
                li.className = 'legend-item';
                li.innerHTML = `
                    <span class="legend-color-box" style="background-color: ${slice.color}; box-shadow: 0 0 6px ${slice.color}66;"></span>
                    <span>${escapeHtml(slice.label)}: ${slice.count} (${slice.percent}%)</span>
                `;
                legendEl.appendChild(li);
            });
        }
    }

    // 9. Table Register Search & Filtering
    const tableSearch = document.getElementById('tableSearch');
    if (tableSearch) {
        tableSearch.addEventListener('input', () => {
            const query = tableSearch.value.toLowerCase().trim();
            const rows = threatTableBody.querySelectorAll('tr');

            rows.forEach(row => {
                const cells = Array.from(row.querySelectorAll('td'));
                const matches = cells.some(cell => cell.textContent.toLowerCase().includes(query));
                row.style.display = matches ? '' : 'none';
            });
        });
    }

    // 10. CSV Log Telemetry Exporter
    const exportCsvBtn = document.getElementById('exportCsvBtn');
    if (exportCsvBtn) {
        exportCsvBtn.addEventListener('click', () => {
            if (scanResults.length === 0) return;

            let csvContent = 'data:text/csv;charset=utf-8,';
            csvContent += 'ID,Attack Type,Severity,Confidence,Status,Recommendation,Alert\n';

            scanResults.forEach((row, idx) => {
                const recText = row.recommendation.replace(/"/g, '""');
                const typeText = row.attack_type.replace(/"/g, '""');
                const alertText = row.alert ? row.alert.replace(/"/g, '""') : '';
                
                csvContent += `"${idx+1}","${typeText}","${row.severity}","${row.confidence}","${row.status}","${recText}","${alertText}"\n`;
            });

            const encodedUri = encodeURI(csvContent);
            const link = document.createElement('a');
            link.setAttribute('href', encodedUri);
            link.setAttribute('download', `aegis_threat_telemetry_${Date.now()}.csv`);
            document.body.appendChild(link);
            link.click();
            document.body.removeChild(link);
            showTerminalLog('CSV telemetry registers exported successfully.', 'success');
        });
    }

    // Escaper
    function escapeHtml(str) {
        if (!str) return '';
        return str
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }
});
// ===========================
// AI-CYBER SHIELD CHATBOT
// ===========================
function resetChat() {
    chatOutput.innerHTML = `
        <div class="bot-message">
            Hello, I am AI-CYBER SHIELD. Ask me about the detected threat, prevention methods, severity, recommendations, or IDS functionality.
        </div>
    `;
}

function updateChatMode() {

    const isPrompt = selectedMode === "prompt";

    chatInput.disabled = !isPrompt;
    chatSendBtn.disabled = !isPrompt;

    chatInput.placeholder = isPrompt
        ? "Ask AI-CYBER SHIELD..."
        : "Questions are disabled in Auto Mode";

    chatSendBtn.style.pointerEvents = isPrompt ? "auto" : "none";
    chatSendBtn.style.cursor = isPrompt ? "pointer" : "not-allowed";
    chatSendBtn.style.opacity = isPrompt ? "1" : "0.5";
}
const chatInput = document.getElementById("chatInput");
const chatSendBtn = document.getElementById("chatSendBtn");
const chatOutput = document.getElementById("chatOutput");
let selectedMode = "auto";
updateChatMode();

const modeButtons =
document.querySelectorAll(".mode-btn");

modeButtons.forEach(btn => {

    btn.addEventListener("click", () => {

        modeButtons.forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        selectedMode = btn.dataset.mode;
        updateChatMode();

        const modeTitle = document.getElementById("modeTitle");
        const modeDescription = document.getElementById("modeDescription");

        if (selectedMode === "auto") {

            modeTitle.textContent = "🤖 Automated Response Mode";
            modeDescription.textContent =
                "AI automatically generates reports and recommendations.";

            // Disable chat
            chatInput.value = "";
            chatInput.disabled = true;
            chatInput.placeholder = "Questions are disabled in Auto Mode";
            chatSendBtn.disabled = true;

        }

        if (selectedMode === "prompt") {

            modeTitle.textContent = "💬 Prompt Mode";
            modeDescription.textContent =
                "User provides prompts to receive information and actions.";

            // Enable chat
            chatInput.disabled = false;
            chatInput.placeholder = "Ask AI-CYBER SHIELD...";
            chatSendBtn.disabled = false;
            //reset chat output
            resetChat();
        }

    });
});
async function sendCyberShieldQuestion() {
    if (selectedMode === "auto") {
        return;
    }
    const question = chatInput.value.trim();
    if (!question) return;

    const userMessage = document.createElement("div");
    userMessage.className = "user-message";
    userMessage.innerText = `[${selectedMode.toUpperCase()}] You: ${question}`;
    chatOutput.appendChild(userMessage);

    chatInput.value = "";

    const botLoading = document.createElement("div");
    botLoading.className = "bot-message";
    botLoading.innerText = "AI-CYBER SHIELD: analyzing query...";
    chatOutput.appendChild(botLoading);

    try {

        const response = await fetch(
            "http://127.0.0.1:5000/ask_cybershield",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    question: question,
                    context: latestThreatContext,
                    mode: selectedMode
                })
            }
        );

        const result = await response.json();

        // -----------------------
        // PROMPT MODE
        // -----------------------
        if (selectedMode === "prompt") {

            botLoading.innerText =
                "AI-CYBER SHIELD: " + result.answer;

        }

        // -----------------------
        // AUTO MODE
        // -----------------------
        else {

            botLoading.innerText =
                "AI-CYBER SHIELD: Generating autonomous report...";

            generateAutoCyberShieldSummary(result);

        }

    }
    catch (error) {

        botLoading.innerText =
            "AI-CYBER SHIELD: Unable to connect to backend.";

        console.error(error);

    }

    chatOutput.scrollTop = chatOutput.scrollHeight;
} // <-- ONLY ONE closing brace here
if (chatSendBtn) {
    chatSendBtn.addEventListener("click", sendCyberShieldQuestion);
}

if (chatInput) {
    chatInput.addEventListener("keypress", function(event) {
        if (event.key === "Enter") {
            sendCyberShieldQuestion();
        }
    });
}
// ===========================
// AI-CYBER SHIELD CHATBOT
// ===========================
function generateAutoCyberShieldSummary(result) {
    const chatOutput = document.getElementById("chatOutput");

    if (!chatOutput || !result) {
        return;
    }
    latestThreatContext = {
    attack_type: result.attack_type || "Unknown",
    status: result.status || "Unknown",
    severity: result.severity || "low",
    confidence: Number(result.confidence || 0),
    explanation: result.explanation || "",
    recommendation: result.recommendation || "",
    adversarial_alert: result.adversarial_alert || "",
    autonomous_response: result.autonomous_response || "",
    preprocessing_summary: result.preprocessing_summary || null
};

console.log("Updated threat context:", latestThreatContext);
const csvHealthInfo =
document.getElementById("csvHealthInfo");
if (result.preprocessing_summary && csvHealthInfo) {
    csvHealthInfo.innerHTML = `
        Uploaded Rows: ${result.preprocessing_summary.uploaded_rows}<br>
        Processed Rows: ${result.preprocessing_summary.processed_rows}<br>
        Removed Rows: ${result.preprocessing_summary.removed_rows}
    `;
}
    let csvSummary = "";

    if (result.preprocessing_summary) {
        const uploaded = result.preprocessing_summary.uploaded_rows;
        const processed = result.preprocessing_summary.processed_rows;
        const removed = result.preprocessing_summary.removed_rows;

        let quality = "Clean";

        if (removed > 0) {
            quality = "Needs Cleaning";
        }

        csvSummary = `
CSV Health:
• Uploaded Rows: ${uploaded}
• Processed Rows: ${processed}
• Removed Rows: ${removed}
• CSV Quality: ${quality}
`;
    }
const adversarialBox =
document.getElementById("adversarialAlert");

if (adversarialBox) {
    adversarialBox.textContent =
        result.adversarial_alert ||
        "No adversarial attack detected.";
}

    // ===========================
// SAVE THREAT HISTORY
// ===========================

let history =
    JSON.parse(localStorage.getItem("threatHistory")) || [];

history.push({
    attackType: result.attack_type,
    severity: result.severity.toUpperCase(),
    confidence: result.confidence.toFixed(2) + "%",
    status: result.status,
    time: new Date().toLocaleString()
});

// Keep only latest 20 entries
if (history.length > 20) {
    history.shift();
}

localStorage.setItem(
    "threatHistory",
    JSON.stringify(history)
);
const defenseStats =
document.getElementById("defenseStats");

if (defenseStats) {
    defenseStats.innerHTML = `
        Threats Learned: ${history.length}<br>
        Last Detection: ${result.attack_type}
    `;
}
const responseBox =
document.getElementById("autonomousResponse");

if (responseBox) {
    responseBox.textContent =
        result.autonomous_response ||
        "No automated response required.";
}

// Refresh history UI
loadHistory();
    const summary = `
🛡 AI-CYBER SHIELD THREAT INTELLIGENCE REPORT

Operating Mode:
${selectedMode === "auto"
 ? "Automated Response Mode"
 : "Prompt Mode"}

Threat Type:
${result.attack_type.toUpperCase()}

Threat Overview:
${result.explanation}

Severity Assessment:
${result.severity.toUpperCase()}

Confidence Score:
${result.confidence.toFixed(2)}%

Recommended Countermeasures:
${result.recommendation}

Autonomous Response:
${result.autonomous_response}

Adversarial Awareness:
${result.adversarial_alert}

CSV Data Quality:
${csvSummary}
`;
    const botMessage = document.createElement("div");
    botMessage.className = "bot-message";
    botMessage.innerText = summary;

    chatOutput.appendChild(botMessage);
    chatOutput.scrollTop = chatOutput.scrollHeight;

}
function loadHistory() {

    let history =
        JSON.parse(localStorage.getItem("threatHistory")) || [];

    const historyBody =
        document.getElementById("historyBody");

    if (!historyBody) return;

    historyBody.innerHTML = "";

    if (history.length === 0) {

        historyBody.innerHTML = `
            <tr>
                <td colspan="6" style="text-align:center;padding:20px;">
                    No threat history available.
                </td>
            </tr>
        `;

        return;
    }

    history.reverse().forEach((item, index) => {

        const tr = document.createElement("tr");

        tr.innerHTML = `
            <td>#${String(index + 1).padStart(3, '0')}</td>
            <td>${item.attackType}</td>
            <td>
                <span class="table-pill ${item.severity.toLowerCase()}">
                    ${item.severity}
                </span>
            </td>
            <td>${item.confidence}</td>
            <td>
                <span class="table-status threat">
                    ${item.status}
                </span>
            </td>
            <td>${item.time}</td>
        `;

        historyBody.appendChild(tr);
    });
}

const historySearch = document.getElementById("historySearch");

if (historySearch) {
    historySearch.addEventListener("input", function () {

        const query = this.value.toLowerCase();

        const rows = document.querySelectorAll("#historyBody tr");

        rows.forEach(row => {
            const text = row.textContent.toLowerCase();

            row.style.display =
                text.includes(query) ? "" : "none";
        });
    });
}
const exportHistoryBtn =
    document.getElementById("exportHistoryBtn");

if (exportHistoryBtn) {

    exportHistoryBtn.addEventListener("click", () => {

        let history =
            JSON.parse(localStorage.getItem("threatHistory")) || [];

        if (history.length === 0) {
            alert("No threat history available.");
            return;
        }

        let csv =
            "ID,Attack Type,Severity,Confidence,Status,Time\n";

        history.forEach((item, index) => {

            csv += `${index + 1},"${item.attackType}","${item.severity}","${item.confidence}","${item.status}","${item.time}"\n`;

        });

        const blob =
            new Blob([csv], { type: "text/csv" });

        const url =
            window.URL.createObjectURL(blob);

        const a =
            document.createElement("a");

        a.href = url;
        a.download = "Threat_History_Report.csv";

        a.click();

        window.URL.revokeObjectURL(url);
    });
}
// ===========================
// LOAD HISTORY ON PAGE OPEN
// ===========================

document.addEventListener("DOMContentLoaded", () => {
    loadHistory();
});

// ===========================
// SECURITY REPORT GENERATOR
// ===========================

const reportBtn = document.getElementById("downloadReport");

if (reportBtn) {

    reportBtn.addEventListener("click", () => {

        if (!latestThreatContext) {
            alert("Run an analysis first.");
            return;
        }

        const report = `
=========================================
AI-CYBER SHIELD SECURITY REPORT
=========================================

Attack Type:
${latestThreatContext.attack_type}

Status:
${latestThreatContext.status}

Severity:
${latestThreatContext.severity}

Confidence:
${latestThreatContext.confidence}%

Explanation:
${latestThreatContext.explanation || "N/A"}

Recommendation:
${latestThreatContext.recommendation}

Adversarial Awareness:
${latestThreatContext.adversarial_alert || "None"}

Autonomous Response:
${latestThreatContext.autonomous_response || "None"}

Generated:
${new Date().toLocaleString()}
`;

        const blob = new Blob([report], {
            type: "text/plain"
        });

        const link = document.createElement("a");

        link.href = URL.createObjectURL(blob);

        link.download =
            "CyberShield_Report.txt";

        link.click();
    });
}