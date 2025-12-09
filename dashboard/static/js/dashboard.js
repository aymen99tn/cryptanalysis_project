// TLS 1.3 Dashboard JavaScript
// Real-time updates using Server-Sent Events (SSE)

// Chart instances
let latencyChart = null;
let documentsChart = null;
let cipherChart = null;

// Data storage
const latencyData = [];
const maxDataPoints = 50;

// Initialize dashboard
document.addEventListener('DOMContentLoaded', () => {
    initializeCharts();
    connectSSE();
    startStatsPolling();
});

// Initialize Chart.js charts
function initializeCharts() {
    const chartOptions = {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
            legend: {
                labels: {
                    color: '#ffffff'
                }
            }
        },
        scales: {
            y: {
                ticks: { color: '#b0b0b0' },
                grid: { color: '#444' }
            },
            x: {
                ticks: { color: '#b0b0b0' },
                grid: { color: '#444' }
            }
        }
    };

    // Latency Chart (Line)
    const latencyCtx = document.getElementById('latencyChart').getContext('2d');
    latencyChart = new Chart(latencyCtx, {
        type: 'line',
        data: {
            labels: [],
            datasets: [{
                label: 'Latency (ms)',
                data: [],
                borderColor: '#4CAF50',
                backgroundColor: 'rgba(76, 175, 80, 0.1)',
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            ...chartOptions,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: { color: '#b0b0b0' },
                    grid: { color: '#444' }
                },
                x: {
                    display: false
                }
            }
        }
    });

    // Documents Chart (Horizontal Bar)
    const documentsCtx = document.getElementById('documentsChart').getContext('2d');
    documentsChart = new Chart(documentsCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: 'Requests',
                data: [],
                backgroundColor: [
                    '#2196F3', '#4CAF50', '#ff9800', '#9C27B0', '#00BCD4',
                    '#FFC107', '#E91E63', '#3F51B5', '#009688', '#795548'
                ]
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    ticks: { color: '#b0b0b0' },
                    grid: { color: '#444' }
                },
                y: {
                    ticks: { color: '#b0b0b0' },
                    grid: { display: false }
                }
            }
        }
    });

    // Cipher Chart (Doughnut)
    const cipherCtx = document.getElementById('cipherChart').getContext('2d');
    cipherChart = new Chart(cipherCtx, {
        type: 'doughnut',
        data: {
            labels: [],
            datasets: [{
                data: [],
                backgroundColor: [
                    '#2196F3', '#4CAF50', '#ff9800', '#9C27B0', '#00BCD4'
                ]
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#ffffff',
                        padding: 15
                    }
                }
            }
        }
    });
}

// Connect to Server-Sent Events
function connectSSE() {
    const eventSource = new EventSource('/api/events');

    eventSource.onmessage = (event) => {
        try {
            const data = JSON.parse(event.data);
            handleEvent(data);
        } catch (e) {
            console.error('Error parsing SSE data:', e);
        }
    };

    eventSource.onerror = (error) => {
        console.error('SSE error:', error);
        // Attempt to reconnect after 5 seconds
        setTimeout(() => {
            console.log('Attempting to reconnect SSE...');
            connectSSE();
        }, 5000);
    };
}

// Handle real-time events
function handleEvent(event) {
    const { type, data } = event;

    switch (type) {
        case 'request':
            addRequestToTable(data);
            updateLatencyChart(data.latency);
            break;
        case 'handshake':
            // Update TLS stats if needed
            break;
        case 'error':
            // Handle errors
            break;
        case 'rate_limit':
            // Handle rate limiting
            break;
    }
}

// Add request to the table
function addRequestToTable(request) {
    const tbody = document.getElementById('requests-body');

    // Remove "no data" row if present
    const noDataRow = tbody.querySelector('.no-data');
    if (noDataRow) {
        tbody.innerHTML = '';
    }

    // Create new row
    const row = document.createElement('tr');
    row.className = 'new-request';

    const time = new Date(request.time).toLocaleTimeString();
    const statusClass = request.status === 'ok' ? 'status-ok' :
                        request.status === 'not_found' ? 'status-error' :
                        'status-warning';
    const statusText = request.status === 'ok' ? '[200]' :
                       request.status === 'not_found' ? '[404]' :
                       `[${request.status}]`;

    row.innerHTML = `
        <td>${time}</td>
        <td>${request.client}</td>
        <td>${request.doc_id}</td>
        <td>${request.latency.toFixed(2)} ms</td>
        <td class="${statusClass}">${statusText}</td>
    `;

    // Insert at the top
    tbody.insertBefore(row, tbody.firstChild);

    // Keep only last 20 rows
    while (tbody.children.length > 20) {
        tbody.removeChild(tbody.lastChild);
    }
}

// Update latency chart
function updateLatencyChart(latency) {
    latencyData.push(latency);

    if (latencyData.length > maxDataPoints) {
        latencyData.shift();
    }

    latencyChart.data.labels = latencyData.map((_, i) => i);
    latencyChart.data.datasets[0].data = latencyData;
    latencyChart.update('none'); // Update without animation for smoother real-time updates
}

// Poll for statistics
function startStatsPolling() {
    updateStats();
    setInterval(updateStats, 2000); // Update every 2 seconds
}

// Update statistics from API
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const data = await response.json();

        // Update status bar
        document.getElementById('uptime').textContent = formatUptime(data.uptime);

        const statusElement = document.getElementById('server-status');
        if (data.status === 'running') {
            statusElement.textContent = '● RUNNING';
            statusElement.className = 'status-value status-running';
        } else {
            statusElement.textContent = '● STOPPED';
            statusElement.className = 'status-value status-stopped';
        }

        // Update stat cards
        document.getElementById('total-connections').textContent = data.total_connections;
        document.getElementById('total-requests').textContent = data.total_requests;
        document.getElementById('total-errors').textContent = data.total_errors;
        document.getElementById('total-rate-limited').textContent = data.total_rate_limited;

        // Update performance metrics
        document.getElementById('avg-latency').textContent = `${data.performance.avg_latency.toFixed(2)} ms`;
        document.getElementById('min-latency').textContent = `${data.performance.min_latency.toFixed(2)} ms`;
        document.getElementById('max-latency').textContent = `${data.performance.max_latency.toFixed(2)} ms`;
        document.getElementById('rps').textContent = data.performance.rps.toFixed(1);

        // Update documents chart
        if (data.top_documents.length > 0) {
            documentsChart.data.labels = data.top_documents.map(d => d.doc_id);
            documentsChart.data.datasets[0].data = data.top_documents.map(d => d.count);
            documentsChart.update();
        }

        // Update cipher chart
        if (data.cipher_distribution.length > 0) {
            cipherChart.data.labels = data.cipher_distribution.map(c =>
                c.cipher.replace('TLS_', '').replace('_SHA384', '').replace('_SHA256', '')
            );
            cipherChart.data.datasets[0].data = data.cipher_distribution.map(c => c.count);
            cipherChart.update();
        }

        // Update recent requests table (if SSE is not working)
        if (data.recent_requests && data.recent_requests.length > 0) {
            updateRequestsTable(data.recent_requests);
        }

    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

// Update requests table from polling (fallback if SSE fails)
function updateRequestsTable(requests) {
    const tbody = document.getElementById('requests-body');

    // Only update if table is empty (SSE not working)
    if (tbody.children.length > 1) {
        return; // SSE is working
    }

    tbody.innerHTML = '';

    if (requests.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="no-data">No requests yet</td></tr>';
        return;
    }

    requests.slice(-20).reverse().forEach(request => {
        const row = document.createElement('tr');

        const time = new Date(request.time).toLocaleTimeString();
        const statusClass = request.status === 'ok' ? 'status-ok' :
                            request.status === 'not_found' ? 'status-error' :
                            'status-warning';
        const statusText = request.status === 'ok' ? '[200]' :
                           request.status === 'not_found' ? '[404]' :
                           `[${request.status}]`;

        row.innerHTML = `
            <td>${time}</td>
            <td>${request.client}</td>
            <td>${request.doc_id}</td>
            <td>${request.latency.toFixed(2)} ms</td>
            <td class="${statusClass}">${statusText}</td>
        `;

        tbody.appendChild(row);
    });
}

// Format uptime
function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);

    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}
