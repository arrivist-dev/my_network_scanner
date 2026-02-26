/**
 * History Page JavaScript Functions
 * Handles history data visualization, charts, and statistics
 */

let scanHistory = [];
let deviceTypes = {};

// Fetch data when the page loads
window.addEventListener('load', function() {
    loadDeviceTypes();
    loadScanHistory();
});

async function loadDeviceTypes() {
    try {
        const response = await fetch('/api/config/device_types');
        deviceTypes = await response.json();
    } catch (error) {
        console.error('Error occurred while loading device types:', error);
    }
}

async function loadScanHistory() {
    try {
        const response = await fetch('/api/scan_history');
        scanHistory = await response.json();
        
        updateStatistics();
        updateDeviceTypeChart();
        updateVendorChart();
        updateTrendChart();
        updateHistoryTable();
        updateTimeline();
        
    } catch (error) {
        console.error('Error occurred while loading history:', error);
    }
}

function updateStatistics() {
    const totalScans = scanHistory.length;
    
    // Get unique devices from the last scan, not total from all scans
    const lastScanDevices = scanHistory.length > 0 ? (scanHistory[scanHistory.length - 1].total_devices || 0) : 0;
    
    // Calculate average devices per scan
    const totalDevicesAllScans = scanHistory.reduce((sum, scan) => sum + (scan.total_devices || 0), 0);
    const avgDevices = totalScans > 0 ? Math.round(totalDevicesAllScans / totalScans) : 0;
    const lastScanDuration = scanHistory.length > 0 ? Math.round(scanHistory[scanHistory.length - 1].scan_duration || 0) : 0;

    document.getElementById('totalScans').textContent = totalScans;
    document.getElementById('totalDevices').textContent = lastScanDevices; // Show last scan's unique devices
    document.getElementById('avgDevices').textContent = avgDevices;
    document.getElementById('lastScanDuration').textContent = lastScanDuration + 's';
}

function updateDeviceTypeChart() {
    const deviceTypeChart = document.getElementById('deviceTypeChart');
    deviceTypeChart.innerHTML = '';

    if (scanHistory.length === 0) {
        deviceTypeChart.innerHTML = '<p style="text-align: center; color: #6c757d;">No scan data yet</p>';
        return;
    }

    const lastScan = scanHistory[scanHistory.length - 1];
    const scanDeviceTypes = lastScan.device_types || {};

    // Create pie chart container
    const chartContainer = document.createElement('div');
    chartContainer.className = 'pie-chart-container';
    
    const pieChart = document.createElement('div');
    pieChart.className = 'pie-chart';
    pieChart.id = 'deviceTypePieChart';
    
    // Tooltip element
    const tooltip = document.createElement('div');
    tooltip.className = 'pie-tooltip';
    tooltip.id = 'pieTooltip';
    
    chartContainer.appendChild(pieChart);
    chartContainer.appendChild(tooltip);
    deviceTypeChart.appendChild(chartContainer);

    // Create pie chart
    createDeviceTypePieChart(scanDeviceTypes);
}

function createDeviceTypePieChart(scanDeviceTypes) {
    const pieChart = document.getElementById('deviceTypePieChart');
    const tooltip = document.getElementById('pieTooltip');
    
    const total = Object.values(scanDeviceTypes).reduce((sum, count) => sum + count, 0);
    if (total === 0) {
        pieChart.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #6c757d;">No data</div>';
        return;
    }

    // Color palette
    const colors = [
        '#667eea', '#764ba2', '#f093fb', '#f5576c', '#4facfe', '#00f2fe',
        '#43e97b', '#38f9d7', '#ffecd2', '#fcb69f', '#a8edea', '#fed6e3',
        '#ff9a9e', '#fecfef', '#ffefd5', '#c471f5', '#fa71cd', '#667eea'
    ];

    let cumulativePercentage = 0;
    let colorIndex = 0;
    
    // Create SVG
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '250');
    svg.setAttribute('height', '250');
    svg.style.transform = 'rotate(-90deg)';

    // Sort device types by count in descending order
    const sortedDeviceTypes = Object.entries(scanDeviceTypes).sort((a, b) => b[1] - a[1]);
    
    sortedDeviceTypes.forEach(([deviceType, count]) => {
        const percentage = (count / total) * 100;
        const circumference = 2 * Math.PI * 100; // radius = 100
        const strokeDasharray = `${(percentage / 100) * circumference} ${circumference}`;
        const strokeDashoffset = -cumulativePercentage * circumference / 100;
        
        // Circle element
        const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
        circle.setAttribute('cx', '125');
        circle.setAttribute('cy', '125');
        circle.setAttribute('r', '100');
        circle.setAttribute('fill', 'transparent');
        circle.setAttribute('stroke', colors[colorIndex % colors.length]);
        circle.setAttribute('stroke-width', '50');
        circle.setAttribute('stroke-dasharray', strokeDasharray);
        circle.setAttribute('stroke-dashoffset', strokeDashoffset);
        circle.style.transition = 'all 0.3s ease';
        circle.style.cursor = 'pointer';
        
        // Hover effects
        circle.addEventListener('mouseenter', (e) => {
            circle.style.strokeWidth = '55';
            circle.style.filter = 'brightness(1.1)';
            
            const icon = getDeviceTypeIcon(deviceType);
            tooltip.innerHTML = `${icon} <strong>${deviceType}</strong><br>${count} devices (${percentage.toFixed(1)}%)`;
            tooltip.style.display = 'block';
        });
        
        circle.addEventListener('mousemove', (e) => {
            const rect = pieChart.getBoundingClientRect();
            tooltip.style.left = (e.clientX - rect.left + 10) + 'px';
            tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
        });
        
        circle.addEventListener('mouseleave', () => {
            circle.style.strokeWidth = '50';
            circle.style.filter = 'none';
            tooltip.style.display = 'none';
        });
        
        svg.appendChild(circle);
        
        cumulativePercentage += percentage;
        colorIndex++;
    });
    
    pieChart.appendChild(svg);
}

function getDeviceTypeIcon(deviceTypeName) {
    // Get icon from device_types.json
    if (deviceTypes[deviceTypeName] && deviceTypes[deviceTypeName].icon) {
        return deviceTypes[deviceTypeName].icon;
    }
    
    // Fallback icons
    const fallbackIcons = {
        'Unknown': '❓',
        'Router': '🌐',
        'Switch': '🔀',
        'Smartphone': '📱',
        'Tablet': '📃',
        'Laptop': '💻',
        'Desktop': '🖥️',
        'Printer': '🖨️',
        'IP Camera': '📹',
        'Smart TV': '📺',
        'Gaming Console': '🎮',
        'Smart Speaker': '🔊',
        'NAS': '💾',
        'IoT Device': '🔗'
    };
    
    return fallbackIcons[deviceTypeName] || '📦';
}

function updateVendorChart() {
    const vendorChart = document.getElementById('vendorChart');
    vendorChart.innerHTML = '';

    if (scanHistory.length === 0) {
        vendorChart.innerHTML = '<p style="text-align: center; color: #6c757d;">No scan data yet</p>';
        return;
    }

    const lastScan = scanHistory[scanHistory.length - 1];
    const vendors = lastScan.vendors || {};

    // Sort vendors by count
    const sortedVendors = Object.entries(vendors).sort((a, b) => b[1] - a[1]);
    const maxCount = Math.max(...Object.values(vendors));

    // Show top 15 vendors
    sortedVendors.slice(0, 15).forEach(([vendor, count]) => {
        const vendorItem = document.createElement('div');
        vendorItem.className = 'vendor-item';
        
        const percentage = (count / maxCount) * 100;
        
        vendorItem.innerHTML = `
            <div class="vendor-name" title="${vendor}">${vendor}</div>
            <div class="vendor-bar">
                <div class="vendor-fill" style="width: ${percentage}%"></div>
            </div>
            <div class="vendor-count">${count}</div>
        `;
        
        vendorChart.appendChild(vendorItem);
    });
}

function updateTrendChart() {
    const trendChart = document.getElementById('trendChart');
    const controlsContainer = document.getElementById('trendChartControls');
    
    if (!trendChart || !controlsContainer) return;
    
    trendChart.innerHTML = '';
    controlsContainer.innerHTML = '';

    if (scanHistory.length === 0) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">No scan data yet</p>';
        return;
    }

    // Get the last 20 scans
    const recentHistory = scanHistory.slice(-20);
    
    if (recentHistory.length < 2) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">At least 2 scans are required to show trends</p>';
        return;
    }

    // Metric definitions
    const metrics = [
        { key: 'total_devices', label: 'Total Devices', color: '#667eea', active: true },
        { key: 'online_devices', label: 'Online Devices', color: '#43e97b', active: true },
        { key: 'scan_duration', label: 'Scan Duration (s)', color: '#f5576c', active: false }
    ];

    // Create control buttons
    metrics.forEach((metric, index) => {
        const toggle = document.createElement('div');
        toggle.className = `metric-toggle ${metric.active ? 'active' : ''}`;
        toggle.innerHTML = `
            <span class="metric-color" style="background-color: ${metric.color}"></span>
            <span>${metric.label}</span>
        `;
        
        toggle.addEventListener('click', () => {
            metric.active = !metric.active;
            toggle.classList.toggle('active', metric.active);
            drawTrendChart(recentHistory, metrics);
        });
        
        controlsContainer.appendChild(toggle);
    });

    // Draw the chart
    drawTrendChart(recentHistory, metrics);
}

function drawTrendChart(data, metrics) {
    const trendChart = document.getElementById('trendChart');
    const tooltip = document.getElementById('chartTooltip');
    
    trendChart.innerHTML = '';

    // Create SVG chart
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('width', '100%');
    svg.setAttribute('height', '380');
    svg.setAttribute('viewBox', '0 0 900 380');
    
    const margin = { top: 20, right: 30, bottom: 80, left: 70 };
    const width = 900 - margin.left - margin.right;
    const height = 380 - margin.top - margin.bottom;

    // Get active metrics
    const activeMetrics = metrics.filter(m => m.active);
    
    if (activeMetrics.length === 0) {
        trendChart.innerHTML = '<p style="text-align: center; color: #6c757d; padding: 60px;">Select at least one metric</p>';
        return;
    }

    // Calculate min/max values for each metric (start Y-axis from 0)
    const metricRanges = {};
    activeMetrics.forEach(metric => {
        const values = data.map(scan => scan[metric.key] || 0);
        metricRanges[metric.key] = {
            min: 0, // Start Y-axis from 0
            max: Math.max(...values),
            range: Math.max(...values) || 1
        };
    });

    // Draw grid lines (only for the first metric)
    const primaryMetric = activeMetrics[0];
    const primaryRange = metricRanges[primaryMetric.key];
    
    for (let i = 0; i <= 5; i++) {
        const y = margin.top + (height * i / 5);
        const value = Math.round(primaryRange.max - (primaryRange.max * i / 5));
        
        // Horizontal grid line
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
        line.setAttribute('x1', margin.left);
        line.setAttribute('y1', y);
        line.setAttribute('x2', margin.left + width);
        line.setAttribute('y2', y);
        line.setAttribute('stroke', '#f0f0f0');
        line.setAttribute('stroke-width', '1');
        svg.appendChild(line);
        
        // Y-axis label
        const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
        text.setAttribute('x', margin.left - 10);
        text.setAttribute('y', y + 5);
        text.setAttribute('text-anchor', 'end');
        text.setAttribute('font-size', '11');
        text.setAttribute('fill', '#6c757d');
        text.textContent = value;
        svg.appendChild(text);
    }

    // Draw area chart for each active metric
    activeMetrics.forEach((metric) => {
        const range = metricRanges[metric.key];
        let pathData = '';
        let areaData = '';
        
        // Starting point (bottom-left corner)
        const startX = margin.left;
        const baselineY = margin.top + height;
        areaData += `M ${startX} ${baselineY}`;
        
        // Data points and path
        data.forEach((scan, index) => {
            const x = margin.left + (width * index / (data.length - 1));
            const normalizedValue = scan[metric.key] / range.range;
            const y = margin.top + height - (normalizedValue * height);
            
            if (index === 0) {
                pathData += `M ${x} ${y}`;
                areaData += ` L ${x} ${y}`;
            } else {
                pathData += ` L ${x} ${y}`;
                areaData += ` L ${x} ${y}`;
            }
            
            // Data point
            const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
            circle.setAttribute('cx', x);
            circle.setAttribute('cy', y);
            circle.setAttribute('r', '4');
            circle.setAttribute('fill', metric.color);
            circle.setAttribute('stroke', 'white');
            circle.setAttribute('stroke-width', '2');
            circle.style.cursor = 'pointer';
            
            // Hover effects
            circle.addEventListener('mouseenter', () => {
                circle.setAttribute('r', '6');
                
                // Tooltip content
                const date = new Date(scan.timestamp).toLocaleDateString('en-US');
                let tooltipHtml = `<div class="tooltip-date">${date}</div>`;
                
                activeMetrics.forEach(m => {
                    const value = scan[m.key] || 0;
                    const unit = m.key === 'scan_duration' ? 's' : '';
                    tooltipHtml += `
                        <div class="tooltip-metric">
                            <div class="tooltip-metric-label">
                                <span class="tooltip-metric-color" style="background-color: ${m.color}"></span>
                                ${m.label}
                            </div>
                            <strong>${value}${unit}</strong>
                        </div>
                    `;
                });
                
                tooltip.innerHTML = tooltipHtml;
                tooltip.style.display = 'block';
            });
            
            circle.addEventListener('mousemove', (e) => {
                const rect = trendChart.getBoundingClientRect();
                tooltip.style.left = (e.clientX - rect.left + 10) + 'px';
                tooltip.style.top = (e.clientY - rect.top - 10) + 'px';
            });
            
            circle.addEventListener('mouseleave', () => {
                circle.setAttribute('r', '4');
                tooltip.style.display = 'none';
            });
            
            svg.appendChild(circle);
        });

        // Close the area path (go to bottom-right corner)
        const endX = margin.left + width;
        areaData += ` L ${endX} ${baselineY} Z`;

        // Area (fill)
        const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        area.setAttribute('d', areaData);
        area.setAttribute('fill', metric.color);
        area.setAttribute('fill-opacity', '0.3');
        area.setAttribute('stroke', 'none');
        svg.appendChild(area);

        // Line (on top of the area)
        const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
        path.setAttribute('d', pathData);
        path.setAttribute('stroke', metric.color);
        path.setAttribute('stroke-width', '3');
        path.setAttribute('fill', 'none');
        path.setAttribute('stroke-linecap', 'round');
        path.setAttribute('stroke-linejoin', 'round');
        svg.appendChild(path);
    });

    // X-axis labels
    data.forEach((scan, index) => {
        if (index % 3 === 0 || index === data.length - 1) {
            const x = margin.left + (width * index / (data.length - 1));
            const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
            text.setAttribute('x', x);
            text.setAttribute('y', margin.top + height + 20);
            text.setAttribute('text-anchor', 'middle');
            text.setAttribute('font-size', '10');
            text.setAttribute('fill', '#6c757d');
            text.setAttribute('transform', `rotate(-45, ${x}, ${margin.top + height + 20})`);
            const date = new Date(scan.timestamp).toLocaleDateString('en-US', { 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
            text.textContent = date;
            svg.appendChild(text);
        }
    });

    // Draw axes
    // Y-axis
    const yAxis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    yAxis.setAttribute('x1', margin.left);
    yAxis.setAttribute('y1', margin.top);
    yAxis.setAttribute('x2', margin.left);
    yAxis.setAttribute('y2', margin.top + height);
    yAxis.setAttribute('stroke', '#2c3e50');
    yAxis.setAttribute('stroke-width', '2');
    svg.appendChild(yAxis);

    // X-axis
    const xAxis = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    xAxis.setAttribute('x1', margin.left);
    xAxis.setAttribute('y1', margin.top + height);
    xAxis.setAttribute('x2', margin.left + width);
    xAxis.setAttribute('y2', margin.top + height);
    xAxis.setAttribute('stroke', '#2c3e50');
    xAxis.setAttribute('stroke-width', '2');
    svg.appendChild(xAxis);

    trendChart.appendChild(svg);
}

function updateHistoryTable() {
    const historyTableBody = document.getElementById('historyTableBody');
    historyTableBody.innerHTML = '';

    if (scanHistory.length === 0) {
        historyTableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: #6c757d;">No scan data yet</td></tr>';
        return;
    }

    // Show the last 20 scans, from the most recent to the oldest
    const recentHistory = scanHistory.slice(-20).reverse();

    recentHistory.forEach((scan, index) => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString('en-US');
        
        // Calculate trend (compare with the previous scan)
        let trendClass = 'trend-stable';
        let trendText = 'Stable';
        
        if (index < recentHistory.length - 1) {
            const prevScan = recentHistory[index + 1];
            const currentDevices = scan.total_devices || 0;
            const prevDevices = prevScan.total_devices || 0;
            
            if (currentDevices > prevDevices) {
                trendClass = 'trend-up';
                trendText = `+${currentDevices - prevDevices}`;
            } else if (currentDevices < prevDevices) {
                trendClass = 'trend-down';
                trendText = `${currentDevices - prevDevices}`;
            }
        }

        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${formattedDate}</td>
            <td>${scan.ip_range || 'N/A'}</td>
            <td>${scan.total_devices || 0}</td>
            <td>${scan.online_devices || 0}</td>
            <td>${Math.round(scan.scan_duration || 0)}s</td>
            <td><span class="trend-indicator ${trendClass}">${trendText}</span></td>
        `;
        
        historyTableBody.appendChild(row);
    });
}

function updateTimeline() {
    const scanTimeline = document.getElementById('scanTimeline');
    scanTimeline.innerHTML = '';

    if (scanHistory.length === 0) {
        scanTimeline.innerHTML = '<p style="text-align: center; color: #6c757d;">No scan data yet</p>';
        return;
    }

    // Show the last 10 scans in the timeline
    const recentHistory = scanHistory.slice(-10).reverse();

    recentHistory.forEach(scan => {
        const date = new Date(scan.timestamp);
        const formattedDate = date.toLocaleString('en-US');
        
        const timelineItem = document.createElement('div');
        timelineItem.className = 'timeline-item';
        
        // Most common device type and vendor
        const scanDeviceTypes = scan.device_types || {};
        const vendors = scan.vendors || {};
        
        const topDeviceType = Object.entries(scanDeviceTypes).sort((a, b) => b[1] - a[1])[0];
        const topVendor = Object.entries(vendors).sort((a, b) => b[1] - a[1])[0];
        
        timelineItem.innerHTML = `
            <div class="timeline-date">${formattedDate}</div>
            <div class="timeline-content">
                <div class="timeline-title">
                    ${scan.total_devices || 0} devices found (${scan.online_devices || 0} online)
                </div>
                <div class="timeline-details">
                    <strong>IP Range:</strong> ${scan.ip_range || 'N/A'}<br>
                    <strong>Scan Duration:</strong> ${Math.round(scan.scan_duration || 0)} seconds<br>
                    ${topDeviceType ? `<strong>Most Common Type:</strong> ${topDeviceType[0]} (${topDeviceType[1]} units)<br>` : ''}
                    ${topVendor ? `<strong>Most Common Brand:</strong> ${topVendor[0]} (${topVendor[1]} units)` : ''}
                </div>
            </div>
        `;
        
        scanTimeline.appendChild(timelineItem);
    });
}

function exportHistory() {
    const dataStr = JSON.stringify(scanHistory, null, 2);
    const dataBlob = new Blob([dataStr], {type: 'application/json'});
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `lan_scanner_history_${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
}

async function clearHistory() {
    if (confirm('Are you sure you want to clear all scan history? This action cannot be undone.')) {
        try {
            const response = await fetch('/api/clear_history', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            const result = await response.json();
            
            if (result.success) {
                scanHistory = [];
                updateStatistics();
                updateDeviceTypeChart();
                updateVendorChart();
                updateTrendChart();
                updateHistoryTable();
                updateTimeline();
                alert('History cleared!');
            } else {
                alert('Error occurred while clearing history: ' + result.error);
            }
        } catch (error) {
            alert('Error occurred while clearing history: ' + error.message);
        }
    }
}

// Automatically refresh the page every 30 seconds
setInterval(loadScanHistory, 30000);