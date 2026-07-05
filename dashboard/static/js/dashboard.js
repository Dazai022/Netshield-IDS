// NetShield IDS/IPS Dashboard JavaScript

let attackTypeChart, attackerChart, timelineChart;
let selectedFile = null;

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    initializeCharts();
    setupEventListeners();
    loadAlerts();
    loadStatistics();
    checkIPSStatus();
});

// Setup event listeners
function setupEventListeners() {
    const uploadArea = document.getElementById('uploadArea');
    const pcapFile = document.getElementById('pcapFile');
    const analyzeBtn = document.getElementById('analyzeBtn');
    const refreshBtn = document.getElementById('refreshBtn');
    const reportBtn = document.getElementById('reportBtn');
    const clearBtn = document.getElementById('clearBtn');
    const ipsToggle = document.getElementById('ipsToggle');

    // File upload
    uploadArea.addEventListener('click', () => pcapFile.click());
    
    uploadArea.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadArea.classList.add('drag-over');
    });
    
    uploadArea.addEventListener('dragleave', () => {
        uploadArea.classList.remove('drag-over');
    });
    
    uploadArea.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadArea.classList.remove('drag-over');
        
        const files = e.dataTransfer.files;
        if (files.length > 0) {
            handleFileSelect(files[0]);
        }
    });
    
    pcapFile.addEventListener('change', (e) => {
        if (e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });
    
    // Analyze button
    analyzeBtn.addEventListener('click', analyzePCAP);
    
    // Control buttons
    refreshBtn.addEventListener('click', () => {
        loadAlerts();
        loadStatistics();
    });
    
    reportBtn.addEventListener('click', downloadReport);
    clearBtn.addEventListener('click', clearAlerts);
    
    // IPS toggle
    ipsToggle.addEventListener('change', toggleIPS);
}

// Handle file selection
function handleFileSelect(file) {
    if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng')) {
        selectedFile = file;
        document.getElementById('analyzeBtn').disabled = false;
        
        const uploadContent = document.querySelector('.upload-content p');
        uploadContent.innerHTML = `<strong>Selected:</strong> ${file.name}`;
    } else {
        alert('Please select a valid PCAP file (.pcap or .pcapng)');
    }
}

// Analyze PCAP file
async function analyzePCAP() {
    if (!selectedFile) return;
    
    const analyzeBtn = document.getElementById('analyzeBtn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const btnLoader = analyzeBtn.querySelector('.btn-loader');
    
    // Show loading state
    btnText.hidden = true;
    btnLoader.hidden = false;
    analyzeBtn.disabled = true;
    
    const formData = new FormData();
    formData.append('pcap_file', selectedFile);
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`Analysis complete! Found ${data.alerts_found} alerts`, 'success');
            loadAlerts();
            loadStatistics();
        } else {
            showNotification(`Error: ${data.error}`, 'error');
        }
    } catch (error) {
        showNotification(`Error analyzing file: ${error.message}`, 'error');
    } finally {
        // Reset button state
        btnText.hidden = false;
        btnLoader.hidden = true;
        analyzeBtn.disabled = false;
    }
}

// Load alerts from API
async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts?limit=100');
        const data = await response.json();
        
        if (data.success) {
            displayAlerts(data.alerts);
        }
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

// Display alerts in table
function displayAlerts(alerts) {
    const tbody = document.getElementById('alertsTableBody');
    
    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="no-data">No alerts detected. Upload a PCAP file to begin analysis.</td></tr>';
        return;
    }
    
    tbody.innerHTML = alerts.reverse().map(alert => `
        <tr>
            <td>${alert.timestamp || 'N/A'}</td>
            <td>${alert.attack || 'Unknown'}</td>
            <td>${alert.src_ip || 'N/A'}</td>
            <td>${alert.dst_ip || 'N/A'}</td>
            <td><span class="severity-badge severity-${alert.severity || 'low'}">${(alert.severity || 'low').toUpperCase()}</span></td>
            <td>${alert.source || 'N/A'}</td>
        </tr>
    `).join('');
}

// Load statistics from API
async function loadStatistics() {
    try {
        const response = await fetch('/api/statistics');
        const data = await response.json();
        
        if (data.success) {
            updateStatistics(data.statistics);
            updateCharts(data.statistics);
        }
    } catch (error) {
        console.error('Error loading statistics:', error);
    }
}

// Update statistics cards
function updateStatistics(stats) {
    document.getElementById('totalAlerts').textContent = stats.total_alerts || 0;
    document.getElementById('highSeverity').textContent = stats.severity_distribution.high || 0;
    document.getElementById('mediumSeverity').textContent = stats.severity_distribution.medium || 0;
    document.getElementById('lowSeverity').textContent = stats.severity_distribution.low || 0;
}

// Initialize charts
function initializeCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
            legend: {
                labels: {
                    color: '#ffffff'
                }
            }
        }
    };
    
    // Attack Type Chart
    const attackTypeCtx = document.getElementById('attackTypeChart').getContext('2d');
    attackTypeChart = new Chart(attackTypeCtx, {
        type: 'pie',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#e74c3c', '#f39c12', '#3498db', '#27ae60', '#9b59b6',
                    '#e67e22', '#1abc9c', '#34495e', '#f1c40f', '#95a5a6'
                ]
            }]
        },
        options: chartOptions
    });
    
    // Attacker Chart
    const attackerCtx = document.getElementById('attackerChart').getContext('2d');
    attackerChart = new Chart(attackerCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Attack Count',
                data: [],
                backgroundColor: '#667eea'
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#ffffff' }
                },
                x: {
                    ticks: { color: '#ffffff' }
                }
            }
        }
    });
    
    // Timeline Chart
    const timelineCtx = document.getElementById('timelineChart').getContext('2d');
    timelineChart = new Chart(timelineCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Attacks Over Time',
                data: [],
                borderColor: '#667eea',
                backgroundColor: 'rgba(102, 126, 234, 0.2)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#ffffff' }
                },
                x: {
                    ticks: { color: '#ffffff' }
                }
            }
        }
    });
}

// Update charts with new data
function updateCharts(stats) {
    // Attack Type Chart
    const attackTypes = Object.entries(stats.attack_type_distribution || {});
    attackTypeChart.data.labels = attackTypes.map(([type]) => type);
    attackTypeChart.data.datasets[0].data = attackTypes.map(([, count]) => count);
    attackTypeChart.update();
    
    // Attacker Chart
    const attackers = stats.top_attackers || [];
    attackerChart.data.labels = attackers.map(a => a.ip);
    attackerChart.data.datasets[0].data = attackers.map(a => a.count);
    attackerChart.update();
    
    // Timeline Chart
    const timeline = stats.timeline || [];
    timelineChart.data.labels = timeline.map(t => t.time);
    timelineChart.data.datasets[0].data = timeline.map(t => t.count);
    timelineChart.update();
}

// Download report
async function downloadReport() {
    try {
        const response = await fetch('/api/report');
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'netshield_report.html';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
            
            showNotification('Report downloaded successfully!', 'success');
        } else {
            showNotification('Error generating report', 'error');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// Clear all alerts
async function clearAlerts() {
    if (!confirm('Are you sure you want to clear all alerts?')) {
        return;
    }
    
    try {
        const response = await fetch('/api/clear', {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification('All alerts cleared', 'success');
            loadAlerts();
            loadStatistics();
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// Toggle IPS auto-blocking
async function toggleIPS() {
    const enabled = document.getElementById('ipsToggle').checked;
    
    try {
        const response = await fetch('/api/ips/toggle', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ enabled })
        });
        
        const data = await response.json();
        
        if (data.success) {
            showNotification(`IPS auto-blocking ${enabled ? 'enabled' : 'disabled'}`, 'success');
        }
    } catch (error) {
        showNotification(`Error: ${error.message}`, 'error');
    }
}

// Check IPS status on load
async function checkIPSStatus() {
    try {
        const response = await fetch('/api/ips/blocked');
        const data = await response.json();
        
        if (data.success) {
            // Update toggle based on current status
            // This is a simplified check - you may want to add a dedicated endpoint
        }
    } catch (error) {
        console.error('Error checking IPS status:', error);
    }
}

// Show notification
function showNotification(message, type = 'info') {
    // Simple alert for now - you can enhance this with a toast library
    alert(message);
}

// Auto-refresh every 30 seconds
setInterval(() => {
    loadAlerts();
    loadStatistics();
}, 30000);
