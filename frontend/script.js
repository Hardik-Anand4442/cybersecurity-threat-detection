/**
 * AegisThreat AI - Cybersecurity Threat Detection System Controller
 */

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
    const stateEmpty = document.getElementById('stateEmpty');
    const stateScanning = document.getElementById('stateScanning');
    const stateResults = document.getElementById('stateResults');
    const scanPercent = document.getElementById('scanPercent');
    const scanStatusMsg = document.getElementById('scanStatusMsg');
    const scanProgressBar = document.getElementById('scanProgressBar');

    if (analyzeBtn) {
        analyzeBtn.addEventListener('click', async () => {
            if (!activeFile) return;

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

        let normalized = [];
        if (Array.isArray(data)) {
            normalized = data.map(item => normalizeData(item));
        } else if (data && typeof data === 'object') {
            if (Array.isArray(data.predictions)) {
                normalized = data.predictions.map(item => normalizeData(item));
            } else if (Array.isArray(data.results)) {
                normalized = data.results.map(item => normalizeData(item));
            } else {
                normalized = [normalizeData(data)];
            }
        }

        if (normalized.length === 0) {
            throw new Error('Detections database parsed empty.');
        }

        scanResults = normalized;
        renderDashboardResults(scanResults);
        setDashboardState('results');
        showTerminalLog(`Ingested ${scanResults.length} live records.`, 'success');
    }

    function normalizeData(item) {
        // Ensure values match requirement lowercase severity and exact field outputs
        return {
            status: item.status || item.Status || 'Malicious',
            attack_type: item.attack_type || item.AttackType || 'Exploits',
            severity: (item.severity || item.Severity || 'low').toLowerCase(),
            confidence: parseFloat(item.confidence || item.Confidence || 50),
            recommendation: item.recommendation || item.Recommendation || 'Investigate suspicious traffic and block source.',
            alert: item.alert || item.Alert || `Threat Detected: ${item.attack_type || 'Exploits'}`
        };
    }

    // 7. Results Dashboard Injections
    const threatStatus = document.getElementById('threatStatus');
    const threatAttackType = document.getElementById('threatAttackType');
    const threatSeverity = document.getElementById('threatSeverity');
    const threatConfidence = document.getElementById('threatConfidence');
    const threatRecommendation = document.getElementById('threatRecommendation');
    const recentAlertMsg = document.getElementById('recentAlertMsg');
    const recentAlertCard = document.querySelector('.recent-alert-card');

    const threatTableBody = document.getElementById('threatTableBody');

    function renderDashboardResults(results) {
        // Render logs registry
        if (threatTableBody) {
            threatTableBody.innerHTML = '';
            results.forEach((row, idx) => {
                const tr = document.createElement('tr');
                tr.dataset.index = idx;
                
                let sevClass = 'medium';
                if (row.severity.includes('crit')) sevClass = 'critical';
                else if (row.severity.includes('high')) sevClass = 'high';
                else if (row.severity.includes('low')) sevClass = 'low';
                else if (row.severity.includes('info')) sevClass = 'info';

                let statusClass = 'neutral';
                const lowerStatus = row.status.toLowerCase();
                if (lowerStatus === 'clean' || lowerStatus === 'cleared') {
                    statusClass = 'clean';
                } else if (lowerStatus === 'malicious' || lowerStatus === 'threat' || lowerStatus === 'suspicious') {
                    statusClass = 'threat';
                }

                tr.innerHTML = `
                    <td style="font-family: var(--font-mono); color: var(--neon-cyan);">#${(idx + 1).toString().padStart(3, '0')}</td>
                    <td style="font-family: var(--font-mono); font-weight: 500;">${escapeHtml(row.attack_type)}</td>
                    <td><span class="table-pill ${sevClass}">${row.severity.toUpperCase()}</span></td>
                    <td style="font-family: var(--font-mono); font-weight: 700;">${row.confidence.toFixed(2)}%</td>
                    <td><span class="table-status ${statusClass}">${escapeHtml(row.status)}</span></td>
                    <td class="table-cell-reco" title="${escapeHtml(row.recommendation)}">${escapeHtml(row.recommendation)}</td>
                `;

                tr.addEventListener('click', () => {
                    document.querySelectorAll('#threatTableBody tr').forEach(r => r.classList.remove('active-row'));
                    tr.classList.add('active-row');
                    loadAnalysisResultCard(row);
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
        if (threatStatus) {
            threatStatus.textContent = row.status;
            threatStatus.className = 'val status-val';
            
            const lowStatus = row.status.toLowerCase();
            if (lowStatus === 'malicious' || lowStatus === 'suspicious') {
                threatStatus.classList.add('malicious');
            }
        }
        if (threatAttackType) threatAttackType.textContent = row.attack_type;
        if (threatSeverity) {
            // Capitalize severity word nicely
            threatSeverity.textContent = row.severity.charAt(0).toUpperCase() + row.severity.slice(1);
        }
        if (threatConfidence) threatConfidence.textContent = `${row.confidence.toFixed(2)}%`;
        if (threatRecommendation) threatRecommendation.textContent = row.recommendation;

        // Populate Recent Alert card (Screenshot 2 specifications)
        if (recentAlertMsg) {
            if (row.alert || (row.status.toLowerCase() !== 'clean' && row.status.toLowerCase() !== 'cleared')) {
                recentAlertMsg.textContent = `Threat Detected: ${row.attack_type}`;
                if (recentAlertCard) recentAlertCard.classList.add('malicious-alert');
            } else {
                recentAlertMsg.textContent = `Safe Log Stream: Clean Broadcast`;
                if (recentAlertCard) recentAlertCard.classList.remove('malicious-alert');
            }
        }
    }

    // 8. Dynamic HTML5 Canvas Pie/Doughnut Chart drawing
    const canvas = document.getElementById('threatDistributionChart');
    const legendEl = document.getElementById('chartLegend');

    function renderDistributionChart(data) {
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        // Aggregate counts by attack type
        const counts = {};
        data.forEach(item => {
            const type = item.attack_type;
            counts[type] = (counts[type] || 0) + 1;
        });

        const total = data.length;
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
