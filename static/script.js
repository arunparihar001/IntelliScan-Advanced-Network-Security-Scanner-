document.addEventListener('DOMContentLoaded', () => {
    const scanButton = document.getElementById('scan-button');
    const ipInput = document.getElementById('ip-address');
    const portInput = document.getElementById('port-range');
    const progressBar = document.getElementById('scan-progress');
    const progressText = document.querySelector('.progress-text');
    const openPortsElement = document.getElementById('open-ports');
    const abuseScoreElement = document.getElementById('abuse-score');
    const riskLevelElement = document.getElementById('risk-level');
    const scanLog = document.getElementById('scan-log');
    const viewHtmlReport = document.getElementById('view-html-report');
    const viewPdfReport = document.getElementById('view-pdf-report');

    let progressInterval = null;

    function updateProgress(percent) {
        progressBar.style.width = `${percent}%`;
        progressText.textContent = `${Math.round(percent)}%`;
    }

    function updateResults(data) {
        if (data.error) {
            throw new Error(data.error);
        }
        openPortsElement.textContent = data.openPorts.length ? data.openPorts.join(', ') : 'None';
        abuseScoreElement.textContent = data.abuseScore;
        riskLevelElement.textContent = data.riskLevel;
        riskLevelElement.className = `result-content risk-${data.riskLevel.toLowerCase()}`;
    }

    function updateLog(message) {
        scanLog.innerHTML += `${message}\n`;
        scanLog.scrollTop = scanLog.scrollHeight;
    }

    function enableReportButtons(htmlFilename, pdfFilename) {
        viewHtmlReport.disabled = false;
        viewPdfReport.disabled = false;
        
        // Update button click handlers
        viewHtmlReport.onclick = () => {
            window.open(`/reports/${htmlFilename}`, '_blank');
        };
        
        viewPdfReport.onclick = () => {
            window.open(`/reports/${pdfFilename}`, '_blank');
        };
    }

    function startProgressUpdates() {
        // Clear any existing interval
        if (progressInterval) {
            clearInterval(progressInterval);
        }

        // Start polling for progress updates
        progressInterval = setInterval(async () => {
            try {
                const response = await fetch('/progress');
                const data = await response.json();
                
                updateProgress(data.progress);
                
                // Update logs
                if (data.logs && data.logs.length > 0) {
                    data.logs.forEach(log => {
                        if (!scanLog.innerHTML.includes(log)) {
                            updateLog(log);
                        }
                    });
                }

                // If scan is complete, stop polling and get results
                if (data.progress >= 100) {
                    clearInterval(progressInterval);
                    await fetchResults();
                }
            } catch (error) {
                console.error('Error fetching progress:', error);
                updateLog(`Error: ${error.message}`);
            }
        }, 100); // Poll every 100ms
    }

    async function fetchResults() {
        try {
            const resultResponse = await fetch('/results');
            const resultData = await resultResponse.json();
            
            if (resultResponse.status === 202) {
                // Scan still in progress, wait and try again
                setTimeout(fetchResults, 1000);
                return;
            }
            
            if (resultResponse.status === 400 || resultData.error) {
                throw new Error(resultData.error || 'Scan failed');
            }
            
            updateResults(resultData);
            if (resultData.htmlReport && resultData.pdfReport) {
                enableReportButtons(resultData.htmlReport, resultData.pdfReport);
            }
        } catch (error) {
            console.error('Error fetching results:', error);
            updateLog(`Error: ${error.message}`);
        } finally {
            scanButton.disabled = false;
        }
    }

    scanButton.addEventListener('click', async () => {
        const ip = ipInput.value.trim();
        const portRange = portInput.value.trim();

        if (!ip || !portRange) {
            alert('Please enter both IP address and port range');
            return;
        }

        // Reset UI
        updateProgress(0);
        openPortsElement.textContent = '-';
        abuseScoreElement.textContent = '-';
        riskLevelElement.textContent = '-';
        riskLevelElement.className = 'result-content';
        scanLog.innerHTML = '';
        viewHtmlReport.disabled = true;
        viewPdfReport.disabled = true;

        try {
            scanButton.disabled = true;
            startProgressUpdates();

            const response = await fetch('/scan', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    ip: ip,
                    portRange: portRange
                })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Failed to start scan');
            }

        } catch (error) {
            updateLog(`Error: ${error.message}`);
            updateProgress(0);
            scanButton.disabled = false;
            if (progressInterval) {
                clearInterval(progressInterval);
            }
        }
    });

    // Input validation
    ipInput.addEventListener('input', () => {
        const ip = ipInput.value.trim();
        const isValid = /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
        ipInput.style.borderColor = isValid ? '' : 'var(--danger-color)';
    });

    portInput.addEventListener('input', () => {
        const portRange = portInput.value.trim();
        const isValid = /^\d+-\d+$/.test(portRange);
        portInput.style.borderColor = isValid ? '' : 'var(--danger-color)';
    });
}); 