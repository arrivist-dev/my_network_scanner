// My Network Scanner (MNS) - Main JavaScript File

let devices = [];
let deviceTypes = {};
let translatedDeviceTypes = {};
let currentEditingIp = null;
let bulkAnalysisResults = {};
let bulkAnalysisRunning = false;
let backgroundAnalysisIndicator = null;
let lastAnalysisMessage = null;

// Table sorting variables
let currentSortColumn = null;
let currentSortDirection = 'asc';

// Progress tracking global variable
let progressInterval = null;

// Language management
async function changeLanguage(languageCode) {
    try {
        const response = await fetch('/api/language/set', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ language: languageCode })
        });
        
        const result = await response.json();
        if (result.success) {
            // Reload the page to apply the new language
            window.location.reload();
        } else {
            console.error('Failed to change language:', result.error);
        }
    } catch (error) {
        console.error('Error changing language:', error);
    }
}

// Fetch data when the page loads
window.addEventListener('load', async function() {
    // Wait for translations to load
    await translationManager.loadTranslations();
    
    await loadDeviceTypes();
    await loadDevices(true); // Update filters on initial load
    initializeTableSorting();
    
    // Check scan status and set button states
    await checkScanStatus();
    
    // Load version information
    await loadVersion();
    
    // Restore active analysis processes
    await restoreActiveAnalyses();
    
    // startProgressUpdates(); - Removed this line, will only run when scanning starts
});

// Initialize table sorting
function initializeTableSorting() {
    const sortableHeaders = document.querySelectorAll('.sortable');
    sortableHeaders.forEach(header => {
        header.addEventListener('click', function() {
            const column = this.getAttribute('data-column');
            const type = this.getAttribute('data-type');
            sortTable(column, type);
        });
    });
    
    // Initially show no sorting, just sort by IP in the background
    currentSortColumn = null; // No column selected
    currentSortDirection = 'asc';
}

// Table sorting function
function sortTable(column, type) {
    // If the same column is clicked, toggle the direction
    if (currentSortColumn === column) {
        currentSortDirection = currentSortDirection === 'asc' ? 'desc' : 'asc';
    } else {
        currentSortColumn = column;
        currentSortDirection = 'asc';
    }
    
    updateSortIndicators();
    displayDevices();
}

// Update sort indicators
function updateSortIndicators() {
    const headers = document.querySelectorAll('.sortable');
    headers.forEach(header => {
        header.classList.remove('asc', 'desc');
        const indicator = header.querySelector('.sort-indicator');
        if (indicator) {
            indicator.innerHTML = '';
        }
    });
    
    const activeHeader = document.querySelector(`[data-column="${currentSortColumn}"]`);
    if (activeHeader) {
        activeHeader.classList.add(currentSortDirection);
        const indicator = activeHeader.querySelector('.sort-indicator');
        if (indicator) {
            indicator.innerHTML = currentSortDirection === 'asc' ? ' ↑' : ' ↓';
        }
    }
}

// Sort devices
function sortDevices(devicesArray) {
    let sortColumn = currentSortColumn || 'ip'; // Default to IP if no column is selected
    let sortDirection = currentSortColumn ? currentSortDirection : 'asc'; // Default to ascending

    return [...devicesArray].sort((a, b) => {
        let aValue, bValue;

        switch (sortColumn) {
            case 'ip': {
                const aIP = a.ip.split('.').map(num => parseInt(num));
                const bIP = b.ip.split('.').map(num => parseInt(num));

                for (let i = 0; i < 4; i++) {
                    if (aIP[i] !== bIP[i]) {
                        const result = aIP[i] - bIP[i];
                        return sortDirection === 'asc' ? result : -result;
                    }
                }
                return 0;
            }
            case 'alias':
                aValue = (a.alias || '').toLowerCase();
                bValue = (b.alias || '').toLowerCase();
                break;
            case 'vendor':
                aValue = (a.vendor || '').toLowerCase();
                bValue = (b.vendor || '').toLowerCase();
                break;
            case 'device_type':
                aValue = (a.device_type || '').toLowerCase();
                bValue = (b.device_type || '').toLowerCase();
                break;
            case 'mac':
                aValue = (a.mac || '').toLowerCase();
                bValue = (b.mac || '').toLowerCase();
                break;
            case 'open_ports':
                aValue = a.open_ports ? a.open_ports.length : 0;
                bValue = b.open_ports ? b.open_ports.length : 0;
                break;
            case 'last_seen':
                aValue = new Date(a.last_seen || 0);
                bValue = new Date(b.last_seen || 0);
                break;
            default:
                return 0;
        }

        // Date sorting
        if (sortColumn === 'last_seen') {
            const result = aValue - bValue;
            return sortDirection === 'asc' ? result : -result;
        }
        
        // Port count sorting
        if (sortColumn === 'open_ports') {
            const result = aValue - bValue;
            return sortDirection === 'asc' ? result : -result;
        }
        
        // Text sorting
        if (aValue < bValue) {
            return sortDirection === 'asc' ? -1 : 1;
        }
        if (aValue > bValue) {
            return sortDirection === 'asc' ? 1 : -1;
        }
        return 0;
    });
}

async function loadDevices(updateFiltersFlag = false) {
    try {
        const response = await fetch('/devices');
        const newDevices = await response.json();
        
        // Update filters only if the device list has changed or explicitly requested
        let shouldUpdateFilters = updateFiltersFlag;
        
        // If filter update is not explicitly requested, check if the device list has changed
        if (!updateFiltersFlag) {
            const oldDevicesStr = JSON.stringify(devices.map(d => ({
                ip: d.ip, 
                device_type: d.device_type, 
                vendor: d.vendor, 
                alias: d.alias,
                open_ports: d.open_ports
            })).sort((a, b) => a.ip.localeCompare(b.ip)));
            
            const newDevicesStr = JSON.stringify(newDevices.map(d => ({
                ip: d.ip, 
                device_type: d.device_type, 
                vendor: d.vendor, 
                alias: d.alias,
                open_ports: d.open_ports
            })).sort((a, b) => a.ip.localeCompare(b.ip)));
            
            shouldUpdateFilters = oldDevicesStr !== newDevicesStr;
        }
        
        devices = newDevices;
        displayDevices();
        updateStats();
        
        if (shouldUpdateFilters) {
            updateFilters();
        }
    } catch (error) {
        console.error(t('device_loading_error'), error);
    }
}

async function loadDeviceTypes() {
    try {
        // Load translated device types
        const response = await fetch('/api/device-types/translated');
        deviceTypes = await response.json();
        
        // Update device type dropdowns
        populateDeviceTypeDropdowns();
    } catch (error) {
        console.error(t('device_types_loading_error'), error);
    }
}

function getTranslatedDeviceType(deviceType) {
    if (!deviceType) return t('unknown');
    
    // Check if we have a translation for this device type
    if (deviceTypes && deviceTypes[deviceType] && deviceTypes[deviceType].name) {
        return deviceTypes[deviceType].name;
    }
    
    // Fallback to original device type
    return deviceType;
}

function populateDeviceTypeDropdowns() {
    // Update edit modal dropdown
    const editDeviceTypeSelect = document.getElementById('editDeviceType');
    if (editDeviceTypeSelect && deviceTypes) {
        editDeviceTypeSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        Object.keys(deviceTypes).sort().forEach(typeName => {
            const option = document.createElement('option');
            option.value = typeName;
            option.textContent = `${deviceTypes[typeName].icon} ${deviceTypes[typeName].name}`;
            editDeviceTypeSelect.appendChild(option);
        });
    }
    
    // Update add device modal dropdown
    const addDeviceTypeSelect = document.getElementById('addDeviceType');
    if (addDeviceTypeSelect && deviceTypes) {
        addDeviceTypeSelect.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        Object.keys(deviceTypes).sort().forEach(typeName => {
            const option = document.createElement('option');
            option.value = typeName;
            option.textContent = `${deviceTypes[typeName].icon} ${typeName}`;
            addDeviceTypeSelect.appendChild(option);
        });
    }
}

function getDeviceIcon(deviceType) {
    return deviceTypes[deviceType]?.icon || '❓';
}

async function checkScanStatus() {
    try {
        const response = await fetch('/progress');
        const progress = await response.json();
        
        // Set button states based on scan status
        if (progress.status === 'scanning') {
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('stopBtn').style.display = 'inline-block';
            document.getElementById('progressContainer').style.display = 'block';
            // Start progress tracking
            startProgressUpdates();
        } else {
            // Idle, completed, error, stopped statuses
            document.getElementById('scanBtn').disabled = false;
            document.getElementById('stopBtn').style.display = 'none';
            document.getElementById('progressContainer').style.display = 'none';
        }
    } catch (error) {
        console.error(t('scan_status_error'), error);
        // In case of error, reset buttons to safe state
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('stopBtn').style.display = 'none';
        document.getElementById('progressContainer').style.display = 'none';
    }
}

function toggleToolsDropdown() {
    const dropdown = document.getElementById('toolsDropdownMenu');
    if (dropdown.style.display === 'none' || dropdown.style.display === '') {
        dropdown.style.display = 'block';
    } else {
        dropdown.style.display = 'none';
    }
}

function closeToolsDropdown() {
    const dropdown = document.getElementById('toolsDropdownMenu');
    dropdown.style.display = 'none';
}

// Close dropdown when clicking outside
document.addEventListener('click', function(event) {
    const dropdown = document.getElementById('toolsDropdownMenu');
    const button = document.getElementById('toolsDropdown');
    
    if (dropdown && button && !dropdown.contains(event.target) && !button.contains(event.target)) {
        dropdown.style.display = 'none';
    }
});

async function loadVersion() {
    try {
        const response = await fetch('/api/version');
        const versionInfo = await response.json();
        
        // Update version information in footer
        const versionElement = document.getElementById('appVersion');
        if (versionElement && versionInfo.version) {
            versionElement.textContent = `v${versionInfo.version}`;
            
            // Add detailed information as tooltip
            if (versionInfo.commit_hash || versionInfo.build_time) {
                let tooltip = [];
                if (versionInfo.commit_hash) {
                    tooltip.push(`Commit: ${versionInfo.commit_hash}`);
                }
                if (versionInfo.commit_count !== null) {
                    tooltip.push(`Commits: ${versionInfo.commit_count}`);
                }
                if (versionInfo.build_time) {
                    const buildDate = new Date(versionInfo.build_time).toLocaleDateString();
                    tooltip.push(`Built: ${buildDate}`);
                }
                if (versionInfo.is_dirty) {
                    tooltip.push('Modified');
                }
                
                versionElement.title = tooltip.join(' | ');
            }
        }
    } catch (error) {
        console.error(t('version_loading_error'), error);
        // Keep default version in case of error
    }
}

function displayDevices() {
    // Call the appropriate display function based on the current view
    switch (currentView) {
        case 'table':
            displayDevicesTable();
            return;
        case 'map':
            displayDevicesMap();
            return;
        default:
            // Card view (default)
            displayDevicesCard();
            return;
    }
}

function displayDevicesCard() {
    const container = document.getElementById('devicesContainer');
    
    if (devices.length === 0) {
        container.innerHTML = `
            <div class="no-devices">
                <i>📡</i>
                <h3>${t('no_devices_message')}</h3>
                <p>${t('scan_to_start')}</p>
            </div>
        `;
        return;
    }

    // Use the sorting function
    const sortedDevices = sortDevices(devices);

    container.innerHTML = sortedDevices.map(device => `
        <div class="device-card">
            <div class="device-header">
                <div class="device-icon">${getDeviceIcon(device.device_type)}</div>
                <div class="device-main-info">
                    <div class="device-ip" onclick="openDevice('${device.ip}')">${device.ip}</div>
                    <div class="device-type">${getTranslatedDeviceType(device.device_type)}</div>
                </div>
                <div class="device-status">
                    ${device.status === 'online' ? '🟢' : '🔴'}
                </div>
            </div>

            ${device.alias ? `<div class="device-alias">👤 ${device.alias}</div>` : ''}
            
            ${device.notes ? `<div class="device-notes">📝 ${device.notes.replace(/\n/g, '<br>')}</div>` : ''}

            <div class="device-details">
                <div class="detail-row">
                    <span class="detail-label">MAC:</span>
                    <span class="detail-value">
                        ${device.mac && device.mac !== 'N/A' ? `
                            <div class="mac-container">
                                <span class="mac-address">${device.mac}</span>
                                <button class="copy-mac-btn" onclick="copyMacAddress('${device.mac}', this); event.stopPropagation();" title="${t('copy_mac_address')}">
                                    📋
                                </button>
                            </div>
                        ` : 'N/A'}
                    </span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Hostname:</span>
                    <span class="detail-value">${device.hostname || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">${t('manufacturer')}:</span>
                    <span class="detail-value">${device.vendor || t('unknown')}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">${t('last_seen')}:</span>
                    <span class="detail-value">${formatDate(device.last_seen)}</span>
                </div>
            </div>

            ${device.open_ports && device.open_ports.length > 0 ? `
                <div class="ports-container">
                    <div class="ports-title">🔌 ${t('open_ports')}</div>
                    <div class="ports-list">
                        ${device.open_ports.map(port => {
                            if (typeof port === 'object') {
                                return `<a href="#" class="port-badge" onclick="openPort('${device.ip}', ${port.port}, '${port.description || port.service || ''}')" title="${port.description || port.service || ''}">
                                    ${port.port}
                                </a>`;
                            } else {
                                return `<a href="#" class="port-badge" onclick="openPort('${device.ip}', ${port}, '')" title="Port ${port}">
                                    ${port}
                                </a>`;
                            }
                        }).join('')}
                    </div>
                </div>
            ` : ''}

            <div class="device-actions">
                <button class="btn btn-primary btn-small" onclick="openEnhancedEditModal('${device.ip}')">✏️ ${t('edit')}</button>
                <button class="btn btn-warning btn-small" onclick="openSingleDeviceAnalysisPage('${device.ip}')" title="${t('advanced_analysis')}">🔬</button>
                ${hasEnhancedInfo(device) ? 
                    `<button class="btn btn-success btn-small" onclick="openEnhancedDetailsModal(${JSON.stringify(device).replace(/"/g, '&quot;')})" title="${t('details')}">📊 ${t('details')}</button>` : 
                    ''
                }
            </div>
        </div>
    `).join('');
}

// Enhanced info check function
function hasEnhancedInfo(device) {
    return device.enhanced_comprehensive_info || 
           device.advanced_scan_summary || 
           device.enhanced_info;
}

function filterDevices() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const deviceTypeFilter = document.getElementById('deviceTypeFilter').value;
    const statusFilter = document.getElementById('statusFilter').value;
    const vendorFilter = document.getElementById('vendorFilter').value;
    const aliasFilter = document.getElementById('aliasFilter').value;
    const portFilter = document.getElementById('portFilter').value;

    const filteredDevices = devices.filter(device => {
        // Search filter
        const matchesSearch = !searchTerm || 
            device.ip.toLowerCase().includes(searchTerm) ||
            (device.mac && device.mac.toLowerCase().includes(searchTerm)) ||
            (device.hostname && device.hostname.toLowerCase().includes(searchTerm)) ||
            (device.vendor && device.vendor.toLowerCase().includes(searchTerm)) ||
            (device.device_type && device.device_type.toLowerCase().includes(searchTerm)) ||
            (device.alias && device.alias.toLowerCase().includes(searchTerm));

        // Device type filter
        const matchesDeviceType = !deviceTypeFilter || device.device_type === deviceTypeFilter;

        // Status filter
        const matchesStatus = !statusFilter || device.status === statusFilter;

        // Vendor filter
        const matchesVendor = !vendorFilter || normalizeVendor(device.vendor) === vendorFilter;

        // Alias filter
        const matchesAlias = !aliasFilter || device.alias === aliasFilter;

        // Port filter - check both automatic and manual ports
        const matchesPort = !portFilter || (device.open_ports && 
            device.open_ports.some(port => {
                const portNumber = typeof port === 'object' ? port.port : port;
                return portNumber.toString() === portFilter;
            }));

        return matchesSearch && matchesDeviceType && matchesStatus && matchesVendor && matchesAlias && matchesPort;
    });

    // Temporarily show filtered devices
    const originalDevices = devices;
    devices = filteredDevices;
    displayDevices();
    updateStats();
    devices = originalDevices;
}

// Variable to track filter update states
let filtersUpdateScheduled = false;

function updateFilters() {
    // If an update is already scheduled, reschedule it
    if (filtersUpdateScheduled) {
        return;
    }
    
    filtersUpdateScheduled = true;
    
    // Run in the next frame (to allow DOM updates to complete)
    requestAnimationFrame(() => {
        performFiltersUpdate();
        filtersUpdateScheduled = false;
    });
}

function performFiltersUpdate() {
    // Save current selected values
    const currentDeviceType = document.getElementById('deviceTypeFilter').value;
    const currentVendor = document.getElementById('vendorFilter').value;
    const currentAlias = document.getElementById('aliasFilter').value;
    const currentPort = document.getElementById('portFilter').value;

    // Device type filter - Show only types found/scanned
    const deviceTypeFilter = document.getElementById('deviceTypeFilter');
    const detectedTypes = [...new Set(devices.map(d => d.device_type).filter(Boolean))].sort();
    
    deviceTypeFilter.innerHTML = `<option value="">${t('all')}</option>` + 
        detectedTypes.map(type => {
            const icon = deviceTypes && deviceTypes[type] ? deviceTypes[type].icon : '';
            const translatedType = getTranslatedDeviceType(type);
            const displayText = icon ? `${icon} ${translatedType}` : translatedType;
            return `<option value="${type}">${displayText}</option>`;
        }).join('');
    
    // Restore selected value (only if still available)
    if (detectedTypes.includes(currentDeviceType) || currentDeviceType === '') {
        deviceTypeFilter.value = currentDeviceType;
    }

    // Vendor filter - Sorted A-Z, normalized
    const vendorFilter = document.getElementById('vendorFilter');
    const vendorOptions = [...new Set(devices.map(d => normalizeVendor(d.vendor)).filter(Boolean))].sort();
    vendorFilter.innerHTML = `<option value="">${t('all')}</option>` + 
        vendorOptions.map(vendor => `<option value="${vendor}">${vendor}</option>`).join('');
    
    // Restore selected value (only if still available)
    if (vendorOptions.includes(currentVendor) || currentVendor === '') {
        vendorFilter.value = currentVendor;
    }

    // Alias filter - Sorted A-Z, non-empty
    const aliasFilter = document.getElementById('aliasFilter');
    const aliasOptions = [...new Set(devices.map(d => d.alias).filter(alias => alias && alias.trim() !== ''))].sort();
    aliasFilter.innerHTML = `<option value="">${t('all')}</option>` + 
        aliasOptions.map(alias => `<option value="${alias}">${alias}</option>`).join('');
    
    // Restore selected value (only if still available)
    if (aliasOptions.includes(currentAlias) || currentAlias === '') {
        aliasFilter.value = currentAlias;
    }

    // Port filter - Include both automatic and manual ports
    const portFilter = document.getElementById('portFilter');
    const allPorts = new Set();
    
    // Add default ports
    ['22', '80', '443', '8080', '3389', '554', '631'].forEach(port => allPorts.add(port));
    
    // Collect all ports from devices
    devices.forEach(device => {
        if (device.open_ports && Array.isArray(device.open_ports)) {
            device.open_ports.forEach(port => {
                const portNumber = typeof port === 'object' ? port.port : port;
                if (portNumber) {
                    allPorts.add(portNumber.toString());
                }
            });
        }
    });
    
    // Create port list
    const sortedPorts = Array.from(allPorts).sort((a, b) => parseInt(a) - parseInt(b));
    const portOptions = sortedPorts.map(port => {
        const portNum = parseInt(port);
        let serviceName = '';
        
        // Add known port names
        const knownPorts = {
            22: 'SSH',
            80: 'HTTP', 
            443: 'HTTPS',
            8080: 'HTTP-Alt',
            3389: 'RDP',
            554: 'RTSP',
            631: 'Printer'
        };
        
        serviceName = knownPorts[portNum] || 'Port';
        return `<option value="${port}">${serviceName} (${port})</option>`;
    }).join('');
    
    portFilter.innerHTML = `<option value="">${t('all')}</option>` + portOptions;
    
    // Restore selected value (only if still available)
    if (Array.from(allPorts).includes(currentPort) || currentPort === '') {
        portFilter.value = currentPort;
    }
}

// Function to normalize vendor names
function normalizeVendor(vendor) {
    if (!vendor) return vendor;
    
    // Merge TP-Link variations
    if (vendor.toLowerCase().includes('tp-link')) {
        return 'TP-Link Systems Inc.';
    }
    
    // Other common normalization
    return vendor.trim();
}

function updateStats() {
    const totalDevices = devices.length;
    const onlineDevices = devices.filter(d => d.status === 'online').length;
    const deviceTypeCount = new Set(devices.map(d => d.device_type).filter(Boolean)).size;
    const vendorCount = new Set(devices.map(d => d.vendor).filter(Boolean)).size;

    document.getElementById('totalDevices').textContent = totalDevices;
    document.getElementById('onlineDevices').textContent = onlineDevices;
    document.getElementById('deviceTypes').textContent = deviceTypeCount;
    document.getElementById('vendors').textContent = vendorCount;
}

function formatDate(dateString) {
    if (!dateString) return 'N/A';
    const date = new Date(dateString);
    return date.toLocaleString('en-US');
}

function openDevice(ip) {
    // Open in a new tab when clicking on the IP address
    window.open(`http://${ip}`, '_blank');
}

function openPort(ip, port, service) {
    // Open the port with the appropriate protocol
    let url = `http://${ip}:${port}`;
    
    if (port === 443 || port === 8443) {
        url = `https://${ip}:${port}`;
    } else if (port === 22) {
        alert(`SSH ${t('connection')}: ssh user@${ip}`);
        return;
    } else if (port === 3389) {
        alert(`RDP ${t('connection')}: ${ip}:${port}`);
        return;
    }
    
    window.open(url, '_blank');
}

function editDevice(ip) {
    const device = devices.find(d => d.ip === ip);
    if (!device) return;

    currentEditingIp = ip;
    
    // Set current values
    document.getElementById('editIpAddress').value = device.ip || '';
    document.getElementById('editMacAddress').value = device.mac || '';
    document.getElementById('editAlias').value = device.alias || '';
    document.getElementById('editHostname').value = device.hostname || '';
    document.getElementById('editVendor').value = device.vendor || '';
    document.getElementById('editDeviceType').value = device.device_type || '';
    document.getElementById('editNotes').value = device.notes || '';
    
    // Load manual ports
    loadManualPorts(device);
    
    document.getElementById('editModal').style.display = 'block';
}

function closeEditModal() {
    document.getElementById('editModal').style.display = 'none';
    currentEditingIp = null;
}

async function saveDevice() {
    if (!currentEditingIp) return;

    // Collect manual ports
    const manualPorts = [];
    const portEntries = document.querySelectorAll('#manualPortsContainer .port-entry');
    portEntries.forEach(entry => {
        const portInput = entry.querySelector('.port-input');
        const descInput = entry.querySelector('.port-desc-input');
        
        if (portInput.value && portInput.value.trim() !== '') {
            manualPorts.push({
                port: parseInt(portInput.value),
                description: descInput.value.trim() || 'Manual Port'
            });
        }
    });

    const data = {
        ip: document.getElementById('editIpAddress').value,
        mac: document.getElementById('editMacAddress').value.toLowerCase(),
        alias: document.getElementById('editAlias').value,
        hostname: document.getElementById('editHostname').value,
        vendor: document.getElementById('editVendor').value,
        device_type: document.getElementById('editDeviceType').value,
        notes: document.getElementById('editNotes').value,
        manual_ports: manualPorts
    };

    try {
        const response = await fetch(`/update_device/${currentEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        if (response.ok) {
            closeEditModal();
            loadDevices(true); // Update filters when the device is updated
            alert(t('device_info_updated'));
        } else {
            const error = await response.json();
            alert(t('error') + ': ' + error.error);
        }
    } catch (error) {
        alert(t('save_error') + ': ' + error.message);
    }
}

let currentAnalysisId = null;
let analysisInterval = null;

async function analyzeDevice(ip) {
    document.getElementById('analysisModal').style.display = 'block';
    document.getElementById('analysisContent').innerHTML = `
        <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
            <button id="closeAnalysisBtn" class="btn btn-secondary" onclick="closeAnalysisModal()">❌ Close</button>
            <button id="backgroundBtn" class="btn btn-info" onclick="continueInBackground()" disabled>🔄 Continue in Background</button>
        </div>
        <div class="analysis-progress">
            <div class="progress-container">
                <div class="progress-bar">
                    <div id="analysisProgressFill" class="progress-fill" style="width: 0%;"></div>
                </div>
                <div id="analysisProgressText" class="progress-text">Starting analysis...</div>
            </div>
        </div>
        <div id="analysisDetails" class="analysis-details" style="margin-top: 20px;">
            <div class="analysis-log">
                <h4>📋 Command Log</h4>
                <div id="commandLog" style="background: #f8f9fa; padding: 15px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.9em;">
                    <div>⏱️ ${new Date().toLocaleTimeString()} - Starting analysis...</div>
                </div>
            </div>
        </div>
    `;

    try {
        // Start background analysis
        const response = await fetch(`/analyze_device_background/${ip}`);
        const result = await response.json();

        if (response.ok) {
            currentAnalysisId = result.analysis_id;
            document.getElementById('backgroundBtn').disabled = false;
            
            // Start progress tracking
            analysisInterval = setInterval(() => {
                updateAnalysisProgress();
            }, 1000);
            
        } else {
            displayAnalysisError(result.error);
        }
    } catch (error) {
        displayAnalysisError(error.message);
    }
}

async function updateAnalysisProgress() {
    if (!currentAnalysisId) return;

    try {
        const response = await fetch(`/analysis_status/${currentAnalysisId}`);
        const status = await response.json();

        if (response.ok) {
            // Update progress bar
            document.getElementById('analysisProgressFill').style.width = status.progress + '%';
            document.getElementById('analysisProgressText').textContent = status.message;

            // Update command log
            const commandLog = document.getElementById('commandLog');
            if (status.commands) {
                let logContent = `<div>⏱️ ${new Date(status.start_time).toLocaleTimeString()} - Analysis started</div>`;
                
                status.commands.forEach(cmd => {
                    const statusIcon = cmd.return_code === 0 ? '✅' : '❌';
                    logContent += `
                        <div style="margin-top: 10px; padding: 10px; background: white; border-radius: 4px;">
                            <div><strong>${statusIcon} ${cmd.name}</strong> (${cmd.duration}s)</div>
                            <div style="color: #6c757d; font-size: 0.8em;">${cmd.command}</div>
                            ${cmd.output ? `<div style="color: #28a745; margin-top: 5px;">${cmd.output.substring(0, 200)}${cmd.output.length > 200 ? '...' : ''}</div>` : ''}
                            ${cmd.error && cmd.error !== 'Timeout' ? `<div style="color: #dc3545; margin-top: 5px;">${cmd.error}</div>` : ''}
                        </div>
                    `;
                });
                
                if (status.current_command) {
                    logContent += `<div style="margin-top: 10px; color: #667eea;"><strong>🔄 Running: ${status.current_command}</strong></div>`;
                }
                
                commandLog.innerHTML = logContent;
                commandLog.scrollTop = commandLog.scrollHeight;
            }

            // Analysis completed
            if (status.status === 'completed') {
                clearInterval(analysisInterval);
                analysisInterval = null;
                
                if (status.result) {
                    displayAnalysisResults(status.result, status);
                }
                
                document.getElementById('backgroundBtn').textContent = '✅ Completed';
                document.getElementById('backgroundBtn').disabled = true;
            } else if (status.status === 'error') {
                clearInterval(analysisInterval);
                analysisInterval = null;
                displayAnalysisError(status.error || status.message);
            }
        } else {
            displayAnalysisError('Could not get analysis status');
        }
    } catch (error) {
        displayAnalysisError('Connection error: ' + error.message);
    }
}

function continueInBackground() {
    if (analysisInterval) {
        clearInterval(analysisInterval);
        analysisInterval = null;
    }
    
    closeAnalysisModal();
    
    // Show notification
    showAlert('Analysis continues in the background. To see the results, click the "Detailed Analysis" button again.', 'info');
}

function displayAnalysisError(error) {
    document.getElementById('analysisContent').innerHTML = `
        <div style="color: #e74c3c; text-align: center; padding: 20px;">
            ❌ Analysis error: ${error}
        </div>
        <div style="text-align: center; margin-top: 15px;">
            <button class="btn btn-secondary" onclick="closeAnalysisModal()">Close</button>
        </div>
    `;
}

function displayAnalysisResults(analysis, statusInfo) {
    const startTime = statusInfo ? new Date(statusInfo.start_time) : new Date();
    const endTime = statusInfo ? new Date(statusInfo.end_time) : new Date();
    const duration = Math.round((endTime - startTime) / 1000);
    
    const content = `
        <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
            <button class="btn btn-secondary" onclick="closeAnalysisModal()">❌ Close</button>
            <button class="btn btn-success">✅ Analysis Completed (${duration}s)</button>
        </div>
        
        <div class="analysis-container">
            <div class="analysis-section">
                <div class="analysis-title">📊 Analysis Summary</div>
                <div class="analysis-result">
                    <strong>Start:</strong> ${startTime.toLocaleString('en-US')}<br>
                    <strong>End:</strong> ${endTime.toLocaleString('en-US')}<br>
                    <strong>Duration:</strong> ${duration} seconds<br>
                    <strong>Commands Run:</strong> ${statusInfo?.commands?.length || 0}
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">🏓 Ping Test</div>
                <div class="analysis-result">
                    ${analysis.ping_test?.success ? 
                        `✅ Successful\n${analysis.ping_test.output}` : 
                        `❌ Failed: ${analysis.ping_test?.error || 'Unknown error'}`
                    }
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">🗺️ Traceroute</div>
                <div class="analysis-result">
                    ${analysis.traceroute?.success ? 
                        analysis.traceroute.output : 
                        `❌ Failed: ${analysis.traceroute?.error || 'Unknown error'}`
                    }
                </div>

            </div>

            <div class="analysis-section">
                <div class="analysis-title">🔍 Service Detection</div>
                <div class="analysis-result">
                    ${Array.isArray(analysis.service_detection) ? 
                        analysis.service_detection.map(service => 
                            `Port ${service.port}: ${service.service} ${service.product} ${service.version}`
                        ).join('\n') || 'No services found' :
                        `❌ Error: ${analysis.service_detection?.error || 'Service detection failed'}`
                    }
                </div>
            </div>

            <div class="analysis-section">
                <div class="analysis-title">💻 Operating System Detection</div>
                <div class="analysis-result">
                    ${analysis.os_detection?.name ? 
                        `${analysis.os_detection.name} (${analysis.os_detection.accuracy}% accuracy)\nFamily: ${analysis.os_detection.family}` :
                        analysis.os_detection?.error ? 
                            `❌ Error: ${analysis.os_detection.error}` :
                            'Operating system could not be detected'
                    }
                </div>
            </div>
            
            ${statusInfo?.commands ? `
            <div class="analysis-section">
                <div class="analysis-title">📋 Commands Run</div>
                <div class="analysis-result">
                    ${statusInfo.commands.map(cmd => `
                        <div style="margin-bottom: 15px; padding: 10px; background: #f8f9fa; border-radius: 6px;">
                            <div><strong>${cmd.return_code === 0 ? '✅' : '❌'} ${cmd.name}</strong> (${cmd.duration}s)</div>
                            <div style="font-family: monospace; font-size: 0.8em; color: #6c757d; margin-top: 5px;">${cmd.command}</div>
                            ${cmd.output ? `<div style="max-height: 100px; overflow-y: auto; margin-top: 8px; padding: 8px; background: white; border-radius: 4px;"><pre style="margin: 0; white-space: pre-wrap;">${cmd.output}</pre></div>` : ''}
                            ${cmd.error && cmd.error !== 'Timeout' ? `<div style="color: #dc3545; margin-top: 5px;">${cmd.error}</div>` : ''}
                        </div>
                    `).join('')}
                </div>
            </div>
            ` : ''}
        </div>
    `;

    document.getElementById('analysisContent').innerHTML = content;
}

function closeAnalysisModal() {
    if (analysisInterval) {
        clearInterval(analysisInterval);
        analysisInterval = null;
    }
    currentAnalysisId = null;
    document.getElementById('analysisModal').style.display = 'none';
}

async function startScan() {
    try {
        const response = await fetch('/scan');
        const result = await response.json();
        
        if (response.ok) {
            document.getElementById('scanBtn').disabled = true;
            document.getElementById('stopBtn').style.display = 'inline-block';
            document.getElementById('progressContainer').style.display = 'block';
            // Show toast notification
            showToast(t('scanning_network'), 'info');
            // Start progress tracking
            startProgressUpdates();
        } else {
            alert(t('scan_start_error') + ': ' + result.error);
        }
    } catch (error) {
        alert(t('scan_start_error') + ': ' + error.message);
    }
}

async function stopScan() {
    try {
        const response = await fetch('/stop_scan');
        const result = await response.json();
        
        document.getElementById('scanBtn').disabled = false;
        document.getElementById('stopBtn').style.display = 'none';
        document.getElementById('progressContainer').style.display = 'none';
        
        // Stop progress interval
        if (progressInterval) {
            clearInterval(progressInterval);
            progressInterval = null;
        }
        
        // Show toast notification
        showToast(result.message, 'warning');
    } catch (error) {
        showToast(t('scan_stop_error') + ': ' + error.message, 'error');
    }
}

function startProgressUpdates() {
    // If there is already a running interval, stop it first
    if (progressInterval) {
        clearInterval(progressInterval);
    }
    
    progressInterval = setInterval(async () => {
        try {
            const response = await fetch('/progress');
            const progress = await response.json();
            
            document.getElementById('progressText').textContent = progress.message;
            
            if (progress.status === 'scanning') {
                document.getElementById('progressFill').style.width = '50%';
            } else if (progress.status === 'completed') {
                document.getElementById('progressFill').style.width = '100%';
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('stopBtn').style.display = 'none';
                
                // Stop interval
                clearInterval(progressInterval);
                progressInterval = null;
                
                // Show toast notification
                showToast(t('scan_complete'), 'success');
                
                setTimeout(() => {
                    document.getElementById('progressContainer').style.display = 'none';
                    // Reload devices and filters when scan is complete
                    loadDevices(true);
                }, 2000);
            } else if (progress.status === 'error') {
                document.getElementById('progressFill').style.width = '0%';
                document.getElementById('scanBtn').disabled = false;
                document.getElementById('stopBtn').style.display = 'none';
                document.getElementById('progressContainer').style.display = 'none';
                
                // Show toast notification
                showToast(t('error') + ': ' + progress.message, 'error');
                
                // Stop interval
                clearInterval(progressInterval);
                progressInterval = null;
            } else if (progress.status === 'idle') {
                // If status is idle and progress is running, stop the interval
                clearInterval(progressInterval);
                progressInterval = null;
            }
            
        } catch (error) {
            console.error(t('error'), error);
        }
    }, 1000);
}

async function exportData() {
    try {
        const response = await fetch('/export');
        const data = await response.json();
        
        const dataStr = JSON.stringify(data, null, 2);
        const dataBlob = new Blob([dataStr], {type: 'application/json'});
        const url = URL.createObjectURL(dataBlob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `lan_devices_${new Date().toISOString().split('T')[0]}.json`;
        link.click();
        URL.revokeObjectURL(url);
    } catch (error) {
        alert(t('export_error') + ': ' + error.message);
    }
}

function importData() {
    const file = document.getElementById('importFile').files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = async function(e) {
            try {
                const importedData = JSON.parse(e.target.result);
                
                const response = await fetch('/import', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(importedData)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    alert(result.message);
                    loadDevices(true); // Update filters after import
                } else {
                    alert(t('import_error') + ': ' + result.error);
                }
            } catch (error) {
                alert(t('file_read_error') + ': ' + error.message);
            }
        };
        reader.readAsText(file);
    }
}

async function sanitizeData() {
    // Ask user for confirmation
    if (!confirm(t('confirm_data_clean'))) {
        return;
    }
    
    try {
        showToast(t('data_cleaning_in_progress'), 'info');
        
        const response = await fetch('/api/sanitize_data', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('data_cleaned_success') + ': ' + result.backup_created, 'success');
            // Reload data
            await loadDevices(true);
        } else {
            showToast(t('data_clean_error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    const editModal = document.getElementById('editModal');
    const analysisModal = document.getElementById('analysisModal');
    
    if (event.target === editModal) {
        closeEditModal();
    }
    if (event.target === analysisModal) {
        closeAnalysisModal();
    }
}

async function startBulkAnalysis() {
    if (devices.length === 0) {
        showToast(t('no_devices_to_analyze'), 'warning');
        return;
    }
    
    if (bulkAnalysisRunning) {
        showToast(t('bulk_analysis_running'), 'warning');
        return;
    }
    
    // If called from unified modal, start analysis directly
    if (window.unifiedAnalysisMode) {
        await startBulkAnalysisActual();
        return;
    }
    
    // Use unified modal
    if (typeof showBulkAnalysisModal === 'function') {
        showBulkAnalysisModal();
    } else {
        // Fallback: old system
        startBulkAnalysisFallback();
    }
}

async function startBulkAnalysisActual() {
    try {
        bulkAnalysisRunning = true;
        
        // Update UI state
        updateBulkAnalysisButtons(true);
        
        // Start bulk detailed analysis using new API
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            showToast(t('bulk_analysis_started'), 'success');
            
            // Start progress tracking
            monitorDetailedAnalysisStatus();
            
        } else {
            throw new Error(result.error || 'Unknown error');
        }
    } catch (error) {
        bulkAnalysisRunning = false;
        updateBulkAnalysisButtons(false);
        showToast(t('analysis_error') + ': ' + error.message, 'error');
    }
}

function updateBulkAnalysisButtons(isRunning) {
    // Update buttons inside unified modal
    const sessionKey = 'bulk';
    const startBtn = document.getElementById(`startBtn_${sessionKey}`);
    const stopBtn = document.getElementById(`stopBtn_${sessionKey}`);
    const minimizeBtn = document.getElementById(`minimizeBtn_${sessionKey}`);
    
    if (startBtn) {
        startBtn.disabled = isRunning;
        startBtn.style.display = isRunning ? 'none' : 'inline-block';
    }
    
    if (stopBtn) {
        stopBtn.style.display = isRunning ? 'inline-block' : 'none';
    }
    
    if (minimizeBtn) {
        minimizeBtn.style.display = isRunning ? 'inline-block' : 'none';
    }
    
    // Show/hide progress section
    const progressDiv = document.getElementById('analysisProgress');
    if (progressDiv) {
        progressDiv.style.display = isRunning ? 'block' : 'none';
    }
}

async function startBulkAnalysisFallback() {
    try {
        // Start bulk detailed analysis using new API
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            bulkAnalysisRunning = true;
            showToast(t('bulk_analysis_started'), 'success');
            
            // Show progress modal
            document.getElementById('analysisModal').style.display = 'block';
            document.getElementById('analysisContent').innerHTML = `
                <div class="analysis-controls" style="margin-bottom: 20px; display: flex; gap: 10px; justify-content: center;">
                    <button class="btn btn-info" onclick="hideBulkAnalysisModal()">📱 Continue in Background</button>
                    <button class="btn btn-success" onclick="loadDevices(true)">🔄 Refresh Data</button>
                </div>
                <div class="analysis-progress">
                    <div class="progress-container">
                        <div class="progress-bar">
                            <div id="bulkAnalysisProgressFill" class="progress-fill" style="width: 0%;"></div>
                        </div>
                        <div id="bulkAnalysisProgressText" class="progress-text">Starting detailed analysis...</div>
                    </div>
                </div>
                <div id="bulkAnalysisDetails" class="analysis-details" style="margin-top: 20px;">
                    <div class="analysis-log">
                        <h4>📋 Detailed Analysis Status</h4>
                        <div id="bulkAnalysisLog" style="background: #f8f9fa; padding: 15px; border-radius: 8px; max-height: 300px; overflow-y: auto; font-family: monospace; font-size: 0.9em;">
                            <div>⏱️ ${new Date().toLocaleTimeString()} - Bulk detailed analysis started</div>
                        </div>
                    </div>
                </div>
            `;
            
            // Monitor analysis status
            monitorDetailedAnalysisStatus();
            
        } else {
            showToast(t('error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function updateBulkAnalysisProgress(percentage, message) {
    // Legacy modal
    const progressFill = document.getElementById('bulkAnalysisProgressFill');
    const progressText = document.getElementById('bulkAnalysisProgressText');
    
    if (progressFill) progressFill.style.width = percentage + '%';
    if (progressText) progressText.textContent = message;
    
    // Unified modal
    const unifiedProgressBar = document.getElementById('progressBar');
    const unifiedProgressText = document.getElementById('progressText');
    
    if (unifiedProgressBar) {
        unifiedProgressBar.style.width = percentage + '%';
        unifiedProgressBar.textContent = Math.round(percentage) + '%';
    }
    if (unifiedProgressText) {
        unifiedProgressText.textContent = message;
    }
}

function updateBulkAnalysisLog(message) {
    // Legacy modal
    const log = document.getElementById('bulkAnalysisLog');
    if (log) {
        const timeStamp = new Date().toLocaleTimeString();
        const newLine = document.createElement('div');
        newLine.textContent = `⏱️ ${timeStamp} - ${message}`;
        log.appendChild(newLine);
        log.scrollTop = log.scrollHeight;
    }
    
    // Unified modal - use addVerboseLog function from device-access.js
    if (typeof addVerboseLog === 'function') {
        addVerboseLog(message, 'bulk');
    }
}

async function monitorBulkAnalysisResults() {
    const checkInterval = setInterval(async () => {
        if (!bulkAnalysisRunning) {
            clearInterval(checkInterval);
            return;
        }
        
        let allCompleted = true;
        let completedCount = 0;
        let totalCount = Object.keys(bulkAnalysisResults).length;
        
        for (const [ip, analyzeData] of Object.entries(bulkAnalysisResults)) {
            if (analyzeData.status === 'running') {
                try {
                    const response = await fetch(`/analysis_status/${analyzeData.analysis_id}`);
                    const status = await response.json();
                    
                    if (status.status === 'completed') {
                        bulkAnalysisResults[ip].status = 'completed';
                        bulkAnalysisResults[ip].result = status;
                        completedCount++;
                        updateBulkAnalysisLog(`✅ ${ip} analysis completed`);
                    } else if (status.status === 'error') {
                        bulkAnalysisResults[ip].status = 'error';
                        bulkAnalysisResults[ip].error = status.error;
                        completedCount++;
                        updateBulkAnalysisLog(`❌ ${ip} analysis error: ${status.error}`);
                    } else {
                        allCompleted = false;
                    }
                } catch (error) {
                    bulkAnalysisResults[ip].status = 'error';
                    bulkAnalysisResults[ip].error = error.message;
                    completedCount++;
                    updateBulkAnalysisLog(`❌ ${ip} status check error: ${error.message}`);
                }
            } else {
                completedCount++;
            }
        }
        
        updateBulkAnalysisProgress((completedCount / totalCount) * 100, `${completedCount}/${totalCount} analyses completed`);
        
        if (allCompleted) {
            clearInterval(checkInterval);
            bulkAnalysisRunning = false;
            updateBulkAnalysisLog(`🎉 Bulk analysis completed! ${completedCount} devices analyzed.`);
            updateBulkAnalysisProgress(100, 'Bulk analysis completed');
            
            // Show toast notification
            showToast(t('bulk_analysis_completed') + '! ' + completedCount + ' ' + t('devices_analyzed'), 'success');
        }
    }, 3000); // Check every 3 seconds
}

function monitorDetailedAnalysisStatus() {
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch('/detailed_analysis_status');
            const status = await response.json();
            
            if (status.status === 'analyzing') {
                // Log new message if available
                if (status.message !== lastAnalysisMessage) {
                    updateBulkAnalysisLog(`🔄 ${status.message}`);
                    lastAnalysisMessage = status.message;
                }
                
                // Update background indicator
                updateBackgroundIndicator(status.message);
                
                // Simulate progress (real progress should come from backend)
                const currentProgress = document.getElementById('bulkAnalysisProgressFill')?.style.width || '0%';
                const progressValue = parseFloat(currentProgress.replace('%', '')) || 0;
                if (progressValue < 90) {
                    updateBulkAnalysisProgress(progressValue + 2, status.message);
                }
            } else if (status.status === 'completed') {
                clearInterval(checkInterval);
                bulkAnalysisRunning = false;
                updateBulkAnalysisLog(`🎉 ${status.message}`);
                updateBulkAnalysisProgress(100, 'Detailed analysis completed');
                showToast(t('bulk_analysis_completed'), 'success');
                hideBackgroundIndicator();
                
                // Update unified modal buttons
                updateBulkAnalysisButtons(false);
                if (typeof updateUnifiedAnalysisButtons === 'function') {
                    updateUnifiedAnalysisButtons('bulk', false);
                }
                
                // Refresh device list
                await loadDevices(true);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                bulkAnalysisRunning = false;
                updateBulkAnalysisLog(`❌ ${status.message}`);
                showToast(t('analysis_error') + ': ' + status.message, 'error');
                hideBackgroundIndicator();
                
                // Update unified modal buttons
                updateBulkAnalysisButtons(false);
                if (typeof updateUnifiedAnalysisButtons === 'function') {
                    updateUnifiedAnalysisButtons('bulk', false);
                }
            }
        } catch (error) {
            console.error('Analysis status check error:', error);
        }
    }, 1500); // Check more frequently (1.5 seconds)
}

function stopBulkAnalysis() {
    bulkAnalysisRunning = false;
    updateBulkAnalysisLog(`⏹️ Bulk analysis stopped`);
    showToast(t('bulk_analysis_stopped'), 'warning');
}

function hideBulkAnalysisModal() {
    document.getElementById('analysisModal').style.display = 'none';
    
    // Check if background analysis is still running
    if (bulkAnalysisRunning) {
        showBackgroundIndicator();
    }
}

// Open Detailed Device Analysis page - compatible with device-access.js
function openSingleDeviceAnalysisPage(ip) {
    // Call showSingleDeviceAnalysisModal function from device-access.js
    if (typeof showSingleDeviceAnalysisModal === 'function') {
        showSingleDeviceAnalysisModal(ip);
    } else {
        // Fallback: use old analysis function
        analyzeSingleDeviceFallback(ip);
    }
}

async function analyzeSingleDeviceFallback(ip) {
    try {
        // Use enhanced analysis endpoint
        const response = await fetch(`/enhanced_analysis/${ip}`, {
            method: 'POST'
        });
        const result = await response.json();
        
        if (response.ok) {
            showToast(`🔬 ${ip} ${t('advanced_analysis_started')}`, 'success');
            
            // Show progress indicator
            updateBackgroundIndicator('Performing enhanced analysis...', true);
            
            // Monitor analysis status
            const checkInterval = setInterval(async () => {
                try {
                    const statusResponse = await fetch(`/enhanced_analysis_status/${ip}`);
                    const status = await statusResponse.json();
                    
                    if (status.status === 'completed') {
                        clearInterval(checkInterval);
                        updateBackgroundIndicator('Enhanced analysis completed', false);
                        showToast(`🎉 ${ip} ${t('advanced_analysis_completed')}`, 'success');
                        await loadDevices(true); // Refresh device list
                    } else if (status.status === 'error') {
                        clearInterval(checkInterval);
                        updateBackgroundIndicator('Analysis error', false);
                        showToast(`❌ ${ip} ${t('analysis_error')}: ${status.message}`, 'error');
                    } else if (status.status === 'analyzing' && status.message) {
                        // Update progress message
                        updateBackgroundIndicator(status.message, true);
                    }
                } catch (error) {
                    console.error('Single device analysis status check error:', error);
                }
            }, 2000);
            
        } else {
            showToast(t('error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function addPortEntry() {
    const container = document.getElementById('manualPortsContainer');
    const newEntry = document.createElement('div');
    newEntry.className = 'port-entry';
    newEntry.innerHTML = `
        <input type="number" placeholder="Port (e.g., 80)" class="port-input" min="1" max="65535">
        <input type="text" placeholder="Description (e.g., HTTP)" class="port-desc-input">
        <button type="button" class="btn btn-danger btn-small" onclick="removePortEntry(this)">🗑️</button>
    `;
    container.appendChild(newEntry);
}

function removePortEntry(button) {
    const container = document.getElementById('manualPortsContainer');
    if (container.children.length > 1) {
        button.parentElement.remove();
    }
}

function showAlert(message, type = 'info') {
    // Simple alert display - more advanced notification system can be added
    alert(message);
}

function loadManualPorts(device) {
    const container = document.getElementById('manualPortsContainer');
    
    // Clear container (leave only the first entry)
    container.innerHTML = `
        <div class="port-entry">
            <input type="number" placeholder="Port (e.g., 80)" class="port-input" min="1" max="65535">
            <input type="text" placeholder="Description (e.g., HTTP)" class="port-desc-input">
            <button type="button" class="btn btn-danger btn-small" onclick="removePortEntry(this)">🗑️</button>
        </div>
    `;
    
    // Load existing manual ports
    if (device.open_ports && Array.isArray(device.open_ports)) {
        const manualPorts = device.open_ports.filter(port => {
            return typeof port === 'object' && port.manual === true;
        });
        
        if (manualPorts.length > 0) {
            // Use the existing entry for the first manual port
            const firstEntry = container.querySelector('.port-entry');
            const firstPort = manualPorts[0];
            firstEntry.querySelector('.port-input').value = firstPort.port;
            firstEntry.querySelector('.port-desc-input').value = firstPort.description || '';
            
            // Add new entries for the remaining ports
            for (let i = 1; i < manualPorts.length; i++) {
                const port = manualPorts[i];
                addPortEntry();
                const newEntry = container.lastElementChild;
                newEntry.querySelector('.port-input').value = port.port;
                newEntry.querySelector('.port-desc-input').value = port.description || '';
            }
        }
    }
}

// View Management
let currentView = 'card'; // Default view

function switchView(view) {
    // Remove active class from previous button (for both old and new buttons)
    document.querySelectorAll('.view-btn, .view-btn-vertical').forEach(btn => btn.classList.remove('active'));
    
    // Add active class to the new button
    document.getElementById(`view${view.charAt(0).toUpperCase() + view.slice(1)}`).classList.add('active');
    
    // Hide/show views
    document.getElementById('devicesContainer').style.display = view === 'card' ? 'grid' : 'none';
    document.getElementById('tableContainer').style.display = view === 'table' ? 'block' : 'none';
    document.getElementById('mapContainer').style.display = view === 'map' ? 'block' : 'none';
    
    currentView = view;
    
    // Load data based on the selected view
    switch (view) {
        case 'card':
            displayDevices(); // Current card view
            break;
        case 'table':
            displayDevicesTable();
            break;
        case 'map':
            displayDevicesMap();
            break;
    }
}

function displayDevicesTable() {
    const tableBody = document.querySelector('#devicesTable tbody');
    
    if (devices.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; padding: 40px; color: #6c757d;">
                    <div>📡 No devices found yet</div>
                    <div style="margin-top: 10px; font-size: 0.9em;">Click "Start Scan" to scan your network</div>
                </td>
            </tr>
        `;
        return;
    }

    // Use the sorting function
    const sortedDevices = sortDevices(devices);

    tableBody.innerHTML = sortedDevices.map(device => {
        const ports = device.open_ports && device.open_ports.length > 0 ? 
            device.open_ports.map(port => {
                if (typeof port === 'object') {
                    return `<span class="port-badge" onclick="openPort('${device.ip}', ${port.port}, '${port.description || port.service || ''}')" title="${port.description || port.service || ''}">${port.port}</span>`;
                } else {
                    return `<span class="port-badge" onclick="openPort('${device.ip}', ${port}, '')" title="Port ${port}">${port}</span>`;
                }
            }).join(' ') : 
            '<span style="color: #6c757d;">-</span>';

        return `
            <tr class="table-row" onclick="selectTableRow(this)">
                <td class="table-cell">
                    <div class="ip-cell" onclick="openDevice('${device.ip}'); event.stopPropagation();">
                        <span class="device-status ${device.status === 'online' ? 'online' : 'offline'}">${device.status === 'online' ? '🟢' : '🔴'}</span>
                        ${device.ip}
                    </div>
                </td>
                <td class="table-cell">${device.alias || '-'}</td>
                <td class="table-cell" title="${device.vendor || 'Unknown'}">${truncateText(device.vendor || 'Unknown', 20)}</td>
                <td class="table-cell">
                    <span class="device-type-badge">
                        ${getDeviceIcon(device.device_type)} ${getTranslatedDeviceType(device.device_type)}
                    </span>
                </td>
                <td class="table-cell">
                    ${device.mac && device.mac !== 'N/A' ? `
                        <div class="mac-container">
                            <span class="mac-address" title="${device.mac}">${truncateText(device.mac, 17)}</span>
                            <button class="copy-mac-btn" onclick="copyMacAddress('${device.mac}', this); event.stopPropagation();" title="Copy MAC address">
                                📋
                            </button>
                        </div>
                    ` : '<span class="mac-address">N/A</span>'}
                </td>
                <td class="table-cell">
                    <div class="ports-cell">${ports}</div>
                </td>
                <td class="table-cell" title="${formatDate(device.last_seen)}">
                    ${formatRelativeTime(device.last_seen)}
                </td>
                <td class="table-cell">
                    <div class="device-actions">
                        <button class="btn btn-primary btn-small" onclick="openEnhancedEditModal('${device.ip}'); event.stopPropagation();" title="Edit">✏️</button>
                        <button class="btn btn-warning btn-small" onclick="openSingleDeviceAnalysisPage('${device.ip}'); event.stopPropagation();" title="Advanced Analysis">🔬</button>
                        ${hasEnhancedInfo(device) ? 
                            `<button class="btn btn-success btn-small" onclick="openEnhancedDetailsModal(${JSON.stringify(device).replace(/"/g, '&quot;')}); event.stopPropagation();" title="Detailed Analysis Results">📊</button>` : 
                            ''
                        }
                    </div>
                </td>
            </tr>
        `;
    }).join('');
}

function displayDevicesMap() {
    const mapContainer = document.getElementById('networkDiagram');
    
    if (devices.length === 0) {
        mapContainer.innerHTML = `
            <div style="text-align: center; padding: 40px; color: #6c757d;">
                <div>📡 No devices found yet</div>
                <div style="margin-top: 10px; font-size: 0.9em;">Click "Start Scan" to scan your network</div>
            </div>
        `;
        return;
    }

    // Group network segments (based on the first 3 octets)
    const networkSegments = {};
    devices.forEach(device => {
        const segment = device.ip.split('.').slice(0, 3).join('.');
        if (!networkSegments[segment]) {
            networkSegments[segment] = [];
        }
        networkSegments[segment].push(device);
    });

    let mapHtml = '<div class="network-map">';
    
    Object.keys(networkSegments).forEach(segment => {
        const segmentDevices = networkSegments[segment];
        const routerDevices = segmentDevices.filter(d => d.device_type === 'Router');
        const otherDevices = segmentDevices.filter(d => d.device_type !== 'Router');
        
        mapHtml += `
            <div class="network-segment">
                <div class="segment-header">
                    <h4>🌐 Network: ${segment}.0/24</h4>
                    <span class="device-count">${segmentDevices.length} devices</span>
                </div>
                
                <div class="segment-content">
                    ${routerDevices.length > 0 ? `
                        <div class="router-section">
                            <div class="section-title">🔀 Routers & Gateways</div>
                            <div class="device-grid">
                                ${routerDevices.map(device => createMapDeviceCard(device)).join('')}
                            </div>
                        </div>
                    ` : ''}
                    
                    ${otherDevices.length > 0 ? `
                        <div class="devices-section">
                            <div class="section-title">💻 Connected Devices</div>
                            <div class="device-grid">
                                ${otherDevices.map(device => createMapDeviceCard(device)).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    });
    
    mapHtml += '</div>';
    mapContainer.innerHTML = mapHtml;
}

function createMapDeviceCard(device) {
    const ports = device.open_ports && device.open_ports.length > 0 ? 
        `<div class="map-ports">${device.open_ports.slice(0, 3).map(port => {
            const portNum = typeof port === 'object' ? port.port : port;
            return `<span class="port-mini">${portNum}</span>`;
        }).join('')}${device.open_ports.length > 3 ? '<span class="port-mini">...</span>' : ''}</div>` : '';

    return `
        <div class="map-device-card ${device.status}" onclick="editDevice('${device.ip}')">
            <div class="map-device-header">
                <span class="map-device-icon">${getDeviceIcon(device.device_type)}</span>
                <span class="map-device-status ${device.status}">${device.status === 'online' ? '🟢' : '🔴'}</span>
            </div>
            <div class="map-device-ip" onclick="openDevice('${device.ip}'); event.stopPropagation();">${device.ip}</div>
            <div class="map-device-info">
                <div class="map-device-name">${device.alias || device.hostname || 'Unknown'}</div>
                <div class="map-device-vendor">${truncateText(device.vendor || 'Unknown', 15)}</div>
            </div>
            ${ports}
        </div>
    `;
}

function selectTableRow(row) {
    // Remove selection from previous row
    document.querySelectorAll('.table-row').forEach(r => r.classList.remove('selected'));
    // Select the new row
    row.classList.add('selected');
}

function truncateText(text, maxLength) {
    if (!text) return '';
    return text.length > maxLength ? text.substring(0, maxLength) + '...' : text;
}

function formatRelativeTime(dateString) {
    if (!dateString) return 'N/A';
    
    const date = new Date(dateString);
    const now = new Date();
    const diffMs = now - date;
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMins / 60);
    const diffDays = Math.floor(diffHours / 24);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    return date.toLocaleDateString('en-US');
}

// Toast Notification System
function createToastContainer() {
    let container = document.querySelector('.toast-container');
    if (!container) {
        container = document.createElement('div');
        container.className = 'toast-container';
        document.body.appendChild(container);
    }
    return container;
}

function showToast(message, type = 'info', duration = 5000) {
    const container = createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };
    
    toast.innerHTML = `
        <span class="toast-icon">${icons[type] || icons.info}</span>
        <span class="toast-message">${message}</span>
        <button class="toast-close" onclick="removeToast(this.parentElement)">&times;</button>
    `;
    
    container.appendChild(toast);
    
    // Auto-remove
    setTimeout(() => {
        removeToast(toast);
    }, duration);
    
    return toast;
}

function removeToast(toast) {
    if (toast && toast.parentElement) {
        toast.classList.add('hiding');
        setTimeout(() => {
            if (toast.parentElement) {
                toast.parentElement.removeChild(toast);
            }
        }, 300);
    }
}

// MAC Address Copy Functionality
async function copyMacAddress(macAddress, buttonElement) {
    try {
        // Modern browsers - use clipboard API
        if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(macAddress);
        } else {
            // Fallback - for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = macAddress;
            textArea.style.position = 'fixed';
            textArea.style.left = '-999999px';
            textArea.style.top = '-999999px';
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
        }
        
        // Visual feedback
        const originalText = buttonElement.innerHTML;
        buttonElement.classList.add('copied');
        buttonElement.innerHTML = '✅';
        
        // Toast notification
        showToast(`${t('mac_copied')}: ${macAddress}`, 'success', 2000);
        
        // Reset button after 1.5 seconds
        setTimeout(() => {
            buttonElement.classList.remove('copied');
            buttonElement.innerHTML = originalText;
        }, 1500);
        
    } catch (error) {
        console.error(t('mac_copy_error'), error);
        showToast(t('mac_copy_error'), 'error', 3000);
        
        // Error visual feedback
        const originalText = buttonElement.innerHTML;
        buttonElement.style.background = '#dc3545';
        buttonElement.innerHTML = '❌';
        
        setTimeout(() => {
            buttonElement.style.background = '';
            buttonElement.innerHTML = originalText;
        }, 1500);
    }
}

// Background analysis indicator functions
function showBackgroundIndicator() {
    if (backgroundAnalysisIndicator) return; // Already displayed
    
    // Create background indicator
    backgroundAnalysisIndicator = document.createElement('div');
    backgroundAnalysisIndicator.id = 'backgroundAnalysisIndicator';
    backgroundAnalysisIndicator.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: linear-gradient(45deg, #007bff, #0056b3);
        color: white;
        padding: 15px 20px;
        border-radius: 10px;
        box-shadow: 0 4px 12px rgba(0,123,255,0.3);
        z-index: 10000;
        cursor: pointer;
        animation: pulse 2s infinite;
        font-family: Arial, sans-serif;
        font-size: 14px;
        font-weight: bold;
        transition: transform 0.3s ease;
        max-width: 280px;
    `;
    
    backgroundAnalysisIndicator.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <div style="width: 8px; height: 8px; background: #28a745; border-radius: 50%; animation: blink 1s infinite;"></div>
            <span>🔬 Detailed Analysis In Progress</span>
            <small style="opacity: 0.8; font-size: 12px;">Click to open</small>
        </div>
    `;
    
    // Open modal on click
    backgroundAnalysisIndicator.addEventListener('click', () => {
        document.getElementById('analysisModal').style.display = 'block';
        hideBackgroundIndicator();
    });
    
    // Hover effect
    backgroundAnalysisIndicator.addEventListener('mouseenter', () => {
        backgroundAnalysisIndicator.style.transform = 'scale(1.05)';
    });
    
    backgroundAnalysisIndicator.addEventListener('mouseleave', () => {
        backgroundAnalysisIndicator.style.transform = 'scale(1)';
    });
    
    document.body.appendChild(backgroundAnalysisIndicator);
    
    // Add CSS animations
    if (!document.getElementById('backgroundIndicatorStyles')) {
        const styles = document.createElement('style');
        styles.id = 'backgroundIndicatorStyles';
        styles.textContent = `
            @keyframes pulse {
                0% { box-shadow: 0 4px 12px rgba(0,123,255,0.3); }
                50% { box-shadow: 0 6px 20px rgba(0,123,255,0.5); }
                100% { box-shadow: 0 4px 12px rgba(0,123,255,0.3); }
            }
            @keyframes blink {
                0%, 50% { opacity: 1; }
                51%, 100% { opacity: 0.3; }
            }
        `;
        document.head.appendChild(styles);
    }
}

function hideBackgroundIndicator() {
    if (backgroundAnalysisIndicator) {
        backgroundAnalysisIndicator.remove();
        backgroundAnalysisIndicator = null;
    }
}

function updateBackgroundIndicator(message) {
    if (backgroundAnalysisIndicator) {
        const messageDiv = backgroundAnalysisIndicator.querySelector('span');
        if (messageDiv) {
            // Highlight IP address
            const ipMatch = message.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
            if (ipMatch) {
                messageDiv.innerHTML = `🔬 Analysis: <strong>${ipMatch[0]}</strong>`;
            } else {
                messageDiv.textContent = '🔬 Detailed Analysis In Progress';
            }
        }
    }
}

// Device Management Modal Functions
function showDeviceManagementModal() {
    document.getElementById('deviceManagementModal').style.display = 'block';
    // Update device type dropdowns
    populateDeviceTypeDropdowns();
    // Load device list
    loadDevicesForManagement();
}

function closeDeviceManagementModal() {
    document.getElementById('deviceManagementModal').style.display = 'none';
}

function switchDeviceManagementTab(tab) {
    // Update tab buttons
    const tabButtons = document.querySelectorAll('.device-management-tabs .tab-button');
    tabButtons.forEach(btn => btn.classList.remove('active'));
    
    // Mark active tab button
    event.target.classList.add('active');
    
    // Hide/show tab contents
    const addTab = document.getElementById('addDeviceTab');
    const manageTab = document.getElementById('manageDeviceTab');
    
    if (tab === 'add') {
        addTab.style.display = 'block';
        manageTab.style.display = 'none';
    } else if (tab === 'manage') {
        addTab.style.display = 'none';
        manageTab.style.display = 'block';
        loadDevicesForManagement();
    }
}

// Device add form submit
document.addEventListener('DOMContentLoaded', function() {
    const addDeviceForm = document.getElementById('addDeviceForm');
    if (addDeviceForm) {
        addDeviceForm.addEventListener('submit', function(e) {
            e.preventDefault();
            addManualDevice();
        });
    }
});

async function addManualDevice() {
    const formData = {
        ip: document.getElementById('addDeviceIP').value.trim(),
        mac: document.getElementById('addDeviceMAC').value.trim(),
        hostname: document.getElementById('addDeviceHostname').value.trim(),
        alias: document.getElementById('addDeviceAlias').value.trim(),
        vendor: document.getElementById('addDeviceVendor').value.trim(),
        device_type: document.getElementById('addDeviceType').value,
        notes: document.getElementById('addDeviceNotes').value.trim()
    };
    
    // Validation
    if (!formData.ip) {
        showToast(t('ip_required'), 'error');
        return;
    }
    
    if (!formData.alias) {
        showToast(t('alias_required'), 'error');
        return;
    }
    
    // IP format check
    const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipPattern.test(formData.ip)) {
        showToast(t('invalid_ip_format'), 'error');
        return;
    }
    
    try {
        const response = await fetch('/add_manual_device', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('device_added_success') + ': ' + formData.alias, 'success');
            clearAddDeviceForm();
            // Update main list
            loadDevices(true);
            // Update management list
            loadDevicesForManagement();
        } else {
            showToast(t('device_add_error') + ': ' + result.message, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

function clearAddDeviceForm() {
    document.getElementById('addDeviceIP').value = '';
    document.getElementById('addDeviceMAC').value = '';
    document.getElementById('addDeviceHostname').value = '';
    document.getElementById('addDeviceAlias').value = '';
    document.getElementById('addDeviceVendor').value = '';
    document.getElementById('addDeviceType').value = '';
    document.getElementById('addDeviceNotes').value = '';
}

function loadDevicesForManagement() {
    const tableBody = document.getElementById('deviceTableBody');
    if (!tableBody) return;
    
    tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">📡 Loading devices...</td></tr>';
    
    // Use main devices list
    if (devices && devices.length > 0) {
        let html = '';
        devices.forEach(device => {
            const isOnline = device.status === 'online';
            const statusIcon = isOnline ? '🟢' : '🔴';
            const statusText = isOnline ? 'Online' : 'Offline';
            
            html += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.ip}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.alias || device.hostname || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${getTranslatedDeviceType(device.device_type)}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.vendor || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${statusIcon}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                        <button class="btn btn-primary" onclick="editDeviceFromManagement('${device.ip}')" title="Edit" style="margin-right: 5px; padding: 4px 8px; font-size: 12px;">
                            ✏️
                        </button>
                        <button class="btn btn-danger" onclick="confirmDeleteDevice('${device.ip}')" title="Delete" style="padding: 4px 8px; font-size: 12px;">
                            🗑️
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html || '<tr><td colspan="6" style="text-align: center; padding: 20px;">No devices found yet.</td></tr>';
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">No devices found yet.</td></tr>';
    }
}

function filterDevicesForManagement() {
    const searchInput = document.getElementById('deviceSearchInput');
    if (!searchInput) return;
    
    const searchTerm = searchInput.value.toLowerCase().trim();
    const tableBody = document.getElementById('deviceTableBody');
    if (!tableBody) return;
    
    // If no search term, show all devices
    if (!searchTerm) {
        loadDevicesForManagement();
        return;
    }
    
    // Filter devices by search term
    const filteredDevices = devices.filter(device => {
        const ip = (device.ip || '').toLowerCase();
        const alias = (device.alias || '').toLowerCase();
        const hostname = (device.hostname || '').toLowerCase();
        const vendor = (device.vendor || '').toLowerCase();
        const deviceType = (device.device_type || '').toLowerCase();
        
        return ip.includes(searchTerm) || 
               alias.includes(searchTerm) || 
               hostname.includes(searchTerm) || 
               vendor.includes(searchTerm) || 
               deviceType.includes(searchTerm);
    });
    
    // Show filtered results
    if (filteredDevices.length > 0) {
        let html = '';
        filteredDevices.forEach(device => {
            const isOnline = device.status === 'online';
            const statusIcon = isOnline ? '🟢' : '🔴';
            const statusText = isOnline ? 'Online' : 'Offline';
            
            html += `
                <tr style="border-bottom: 1px solid #eee;">
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.ip}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.alias || device.hostname || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${getTranslatedDeviceType(device.device_type)}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${device.vendor || '-'}</td>
                    <td style="padding: 10px; border: 1px solid #ddd;">${statusIcon} ${statusText}</td>
                    <td style="padding: 10px; border: 1px solid #ddd; text-align: center;">
                        <button class="btn btn-primary" onclick="editDeviceFromManagement('${device.ip}')" title="Edit" style="margin-right: 5px; padding: 4px 8px; font-size: 12px;">
                            ✏️
                        </button>
                        <button class="btn btn-danger" onclick="confirmDeleteDevice('${device.ip}')" title="Delete" style="padding: 4px 8px; font-size: 12px;">
                            🗑️
                        </button>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = html;
    } else {
        tableBody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 20px;">🔍 No devices found matching search criteria.</td></tr>';
    }
}

// Edit button click opens existing edit modal
function editDeviceFromManagement(ip) {
    const device = devices.find(d => d.ip === ip);
    if (!device) {
        showToast(t('device_not_found'), 'error');
        return;
    }
    
    // Close device management modal
    closeDeviceManagementModal();
    
    // Open main page edit modal (use existing editDevice function in main.js)
    editDevice(ip);
}

function confirmDeleteDevice(ip) {
    const device = devices.find(d => d.ip === ip);
    const deviceName = device ? (device.alias || device.hostname || ip) : ip;
    
    if (confirm(`"${deviceName}" ${t('confirm_delete_device')}`)) {
        deleteDevice(ip);
    }
}

async function deleteDevice(ip) {
    try {
        const response = await fetch(`/delete_device/${ip}`, {
            method: 'DELETE'
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast(t('device_deleted_success'), 'success');
            // Update main list
            await loadDevices(true);
            // Update management list
            loadDevicesForManagement();
        } else {
            showToast(t('device_delete_error') + ': ' + result.message, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}

// Restore active analysis processes
async function restoreActiveAnalyses() {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (response.ok && Object.keys(activeAnalyses).length > 0) {
            console.log('Active analysis processes detected, restoring:', activeAnalyses);
            
            for (const [sessionKey, analysisInfo] of Object.entries(activeAnalyses)) {
                if (analysisInfo.type === 'single') {
                    // Restore single device analysis
                    await restoreSingleDeviceAnalysis(sessionKey, analysisInfo);
                } else if (analysisInfo.type === 'bulk') {
                    // Restore bulk analysis
                    await restoreBulkAnalysis(analysisInfo);
                }
            }
            
            showToast(t('active_analysis_restored'), 'info');
        }
    } catch (error) {
        console.error('Active analysis restore error:', error);
    }
}

// Restore single device analysis
async function restoreSingleDeviceAnalysis(ip, analysisInfo) {
    // Check if device-access.js is loaded
    if (typeof showUnifiedAnalysisModal !== 'function') {
        console.warn('device-access.js not loaded, analysis cannot be restored');
        return;
    }
    
    // Create and minimize modal
    showUnifiedAnalysisModal(ip, 'single');
    
    // Minimize after a short delay
    setTimeout(() => {
        if (typeof minimizeAnalysisModal === 'function') {
            minimizeAnalysisModal(ip);
            
            // Show progress in toaster
            if (typeof updateToasterProgress === 'function') {
                const progress = analysisInfo.progress || 0;
                const message = analysisInfo.message || 'Analysis in progress...';
                updateToasterProgress(ip, progress, message);
            }
            
            // Restart monitoring
            if (typeof monitorSingleDeviceAnalysis === 'function') {
                monitorSingleDeviceAnalysis(ip);
            }
        }
    }, 500);
}

// Restore bulk analysis
async function restoreBulkAnalysis(analysisInfo) {
    // Check if device-access.js is loaded
    if (typeof showUnifiedAnalysisModal !== 'function') {
        console.warn('device-access.js not loaded, bulk analysis cannot be restored');
        return;
    }
    
    // Create and minimize modal
    showUnifiedAnalysisModal(null, 'bulk');
    
    // Minimize after a short delay
    setTimeout(() => {
        if (typeof minimizeAnalysisModal === 'function') {
            minimizeAnalysisModal('bulk');
            
            // Show progress in toaster
            if (typeof updateToasterProgress === 'function') {
                const progress = analysisInfo.progress || 0;
                const message = analysisInfo.message || 'Bulk analysis in progress...';
                updateToasterProgress('bulk', progress, message);
            }
            
            // Restart monitoring
            if (typeof monitorBulkAnalysis === 'function') {
                monitorBulkAnalysis();
            }
        }
    }, 500);
}

// Enhanced Edit Modal Functions
let currentEnhancedEditingIp = null;

function openEnhancedEditModal(ip) {
    const device = devices.find(d => d.ip === ip);
    if (!device) {
        showToast(t('device_not_found'), 'error');
        return;
    }

    currentEnhancedEditingIp = ip;
    
    // Load device data to all tabs
    loadDeviceToEnhancedModal(device);
    
    // Show modal
    document.getElementById('enhancedEditModal').style.display = 'block';
    
    // Switch to first tab
    switchEditTab('device');
}

function closeEnhancedEditModal() {
    document.getElementById('enhancedEditModal').style.display = 'none';
    currentEnhancedEditingIp = null;
}

function switchEditTab(tabName) {
    // Hide all tab panes
    const tabPanes = document.querySelectorAll('.tab-pane');
    tabPanes.forEach(pane => pane.classList.remove('active'));
    
    // Remove active class from all buttons
    const tabButtons = document.querySelectorAll('.tab-button');
    tabButtons.forEach(button => button.classList.remove('active'));
    
    // Show selected tab
    document.getElementById(`${tabName}-tab`).classList.add('active');
    
    // Activate selected button - find button by onclick attribute
    const activeButton = document.querySelector(`[onclick*="switchEditTab('${tabName}')"]`);
    if (activeButton) {
        activeButton.classList.add('active');
    }
    
    // Load tab-specific data
    if (tabName === 'ports') {
        loadPortsTab();
    } else if (tabName === 'access') {
        loadAccessTab();
    }
}

function loadDeviceToEnhancedModal(device) {
    // Load device tab data
    document.getElementById('enhancedEditIpAddress').value = device.ip || '';
    document.getElementById('enhancedEditMacAddress').value = device.mac || '';
    document.getElementById('enhancedEditAlias').value = device.alias || '';
    document.getElementById('enhancedEditHostname').value = device.hostname || '';
    document.getElementById('enhancedEditVendor').value = device.vendor || '';
    document.getElementById('enhancedEditNotes').value = device.notes || '';
    
    // Load device types to dropdown first, then set selected value
    loadDeviceTypesToEnhancedModal().then(() => {
        document.getElementById('enhancedEditDeviceType').value = device.device_type || '';
    });
}

async function loadDeviceTypesToEnhancedModal() {
    try {
        const response = await fetch('/api/device-types/translated');
        const types = await response.json();
        
        const select = document.getElementById('enhancedEditDeviceType');
        select.innerHTML = `<option value="">${t('select_device_type')}</option>`;
        
        Object.keys(types).forEach(type => {
            const option = document.createElement('option');
            option.value = type;
            const icon = types[type].icon || '📱';
            const translatedName = types[type].name || type;
            option.textContent = `${icon} ${translatedName}`;
            select.appendChild(option);
        });
    } catch (error) {
        console.error('Device types could not be loaded:', error);
    }
}

function loadPortsTab() {
    if (!currentEnhancedEditingIp) return;
    
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const tableBody = document.getElementById('portsTableBody');
    tableBody.innerHTML = '';
    
    if (device.open_ports && device.open_ports.length > 0) {
        // Sort ports by port number
        const sortedPorts = [...device.open_ports].sort((a, b) => a.port - b.port);
        
        sortedPorts.forEach(port => {
            const row = createPortTableRow(port);
            tableBody.appendChild(row);
        });
    } else {
        tableBody.innerHTML = `
            <tr>
                <td colspan="5" class="text-center text-muted" style="padding: 30px;">
                    No ports found yet. You can add ports using "➕ Add New Port".
                </td>
            </tr>
        `;
    }
}

function createPortTableRow(port) {
    const row = document.createElement('tr');
    const isManual = port.manual || false;
    
    row.innerHTML = `
        <td>
            <span class="port-number">${port.port}</span>
        </td>
        <td>
            ${isManual ? 
                `<input type="text" class="editable-field" value="${port.service || ''}" onchange="updatePortField(${port.port}, 'service', this.value)">` :
                `${port.service || 'Unknown'}`
            }
        </td>
        <td>
            ${isManual ? 
                `<input type="text" class="editable-field" value="${port.description || ''}" onchange="updatePortField(${port.port}, 'description', this.value)">` :
                `${port.description || port.version || '-'}`
            }
        </td>
        <td>
            <span class="port-type ${isManual ? 'manual' : 'auto'}">
                ${isManual ? 'Manual' : 'Automatic'}
            </span>
        </td>
        <td>
            <div class="port-actions">
                ${isManual ? `
                    <button class="port-btn delete" onclick="deletePortFromTable(${port.port})" title="Delete">🗑️</button>
                ` : `
                    <button class="port-btn convert" onclick="convertToManualInTable(${port.port})" title="Convert to Manual">📝</button>
                `}
            </div>
        </td>
    `;
    return row;
}

function addNewPortInline() {
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const tableBody = document.getElementById('portsTableBody');
    
    // Remove empty message if exists
    const emptyRow = tableBody.querySelector('td[colspan="5"]');
    if (emptyRow) {
        emptyRow.parentElement.remove();
    }
    
    // Create new row for editing
    const newRow = document.createElement('tr');
    newRow.style.background = '#fff3cd';
    newRow.innerHTML = `
        <td>
            <input type="number" class="editable-field" placeholder="Port No" min="1" max="65535" id="newPortNumber" required>
        </td>
        <td>
            <input type="text" class="editable-field" placeholder="Service name" id="newPortService">
        </td>
        <td>
            <input type="text" class="editable-field" placeholder="Description" id="newPortDescription">
        </td>
        <td>
            <span class="port-type manual">Manual</span>
        </td>
        <td>
            <div class="port-actions">
                <button class="port-btn edit" onclick="saveNewPort()" title="Save">💾</button>
                <button class="port-btn delete" onclick="cancelNewPort()" title="Cancel">❌</button>
            </div>
        </td>
    `;
    
    tableBody.appendChild(newRow);
    document.getElementById('newPortNumber').focus();
}

function saveNewPort() {
    const portNumber = document.getElementById('newPortNumber').value;
    const portService = document.getElementById('newPortService').value;
    const portDescription = document.getElementById('newPortDescription').value;
    
    if (!portNumber || isNaN(portNumber) || portNumber < 1 || portNumber > 65535) {
        showToast(t('invalid_port_number'), 'error');
        return;
    }
    
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    if (!device.open_ports) device.open_ports = [];
    
    // Check if port already exists
    if (device.open_ports.some(p => p.port == portNumber)) {
        showToast(t('port_already_exists'), 'error');
        return;
    }
    
    device.open_ports.push({
        port: parseInt(portNumber),
        service: portService,
        description: portDescription,
        state: 'open',
        manual: true,
        last_verified: new Date().toISOString()
    });
    
    loadPortsTab();
    showToast(t('port_added_success'), 'success');
}

function cancelNewPort() {
    loadPortsTab(); // Reload to remove the editing row
}

function updatePortField(portNumber, field, value) {
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port[field] = value;
    showToast(t('port_updated_success'), 'success');
}

function deletePortFromTable(portNumber) {
    if (!confirm(t('confirm_delete_port'))) return;
    
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    device.open_ports = device.open_ports.filter(p => p.port != portNumber);
    
    loadPortsTab();
    showToast(t('port_deleted_success'), 'success');
}

function convertToManualInTable(portNumber) {
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port.manual = true;
    loadPortsTab();
    showToast(t('port_manual_mode'), 'success');
}

function editPort(portNumber) {
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    const newService = prompt('Service name:', port.service || '') || '';
    const newDescription = prompt('Description:', port.description || '') || '';
    
    port.service = newService;
    port.description = newDescription;
    
    loadPortsTab();
    showToast(t('port_updated_success'), 'success');
}

function deletePort(portNumber) {
    if (!confirm(t('confirm_delete_port'))) return;
    
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    device.open_ports = device.open_ports.filter(p => p.port != portNumber);
    
    loadPortsTab();
    showToast(t('port_deleted_success'), 'success');
}

function convertToManual(portNumber) {
    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;
    
    const port = device.open_ports.find(p => p.port == portNumber);
    if (!port) return;
    
    port.manual = true;
    loadPortsTab();
    showToast(t('port_manual_mode'), 'success');
}

function refreshDetectedPorts() {
    showToast(t('port_scan_starting'), 'info');
    // This would trigger a port scan for the specific device
    // Implementation depends on backend API
}

function loadAccessTab() {
    // Load existing access credentials
    updateEnhancedAccessForm();
    loadExistingAccessCredentials();
}

async function loadExistingAccessCredentials() {
    if (!currentEnhancedEditingIp) return;
    
    try {
        const accessType = document.getElementById('enhancedAccessType').value || 'ssh';
        const response = await fetch(`/get_device_credentials/${currentEnhancedEditingIp}?access_type=${accessType}`);
        if (response.ok) {
            const credentials = await response.json();
            if (credentials && Object.keys(credentials).length > 0) {
                document.getElementById('enhancedAccessType').value = accessType;
                document.getElementById('enhancedAccessPort').value = credentials.port || '';
                document.getElementById('enhancedAccessUsername').value = credentials.username || '';
                document.getElementById('enhancedAccessPassword').value = credentials.password || '';
                document.getElementById('enhancedAccessNotes').value = credentials.additional_info?.notes || '';
                // Don't call updateEnhancedAccessForm() here to avoid recursion
                updateEnhancedAccessHints();
            } else {
                // Clear fields if no credentials found
                clearAccessFields();
            }
        } else {
            // Clear fields if request failed
            clearAccessFields();
        }
    } catch (error) {
        console.log('Existing access credentials could not be loaded:', error);
        clearAccessFields();
    }
}

function clearAccessFields() {
    document.getElementById('enhancedAccessPort').value = '';
    document.getElementById('enhancedAccessUsername').value = '';
    document.getElementById('enhancedAccessPassword').value = '';
    document.getElementById('enhancedAccessNotes').value = '';
}

function updateEnhancedAccessForm() {
    const accessType = document.getElementById('enhancedAccessType').value;
    const portField = document.getElementById('enhancedAccessPort');
    const hintsDiv = document.getElementById('enhancedAccessHints');
    
    // Auto-set default ports
    const defaultPorts = {
        'ssh': 22,
        'ftp': 21,
        'telnet': 23,
        'http': 80,
        'snmp': 161,
        'api': ''
    };
    
    if (defaultPorts[accessType]) {
        portField.value = defaultPorts[accessType];
    } else {
        portField.value = '';
    }
    
    // Reload credentials for this access type
    loadExistingAccessCredentials();
    
    // Update hints
    updateEnhancedAccessHints();
}

function updateEnhancedAccessHints() {
    const accessType = document.getElementById('enhancedAccessType').value;
    const hintsDiv = document.getElementById('enhancedAccessHints');
    
    // Update hints (reuse existing hints from device-access.js)
    const hints = {
        'ssh': `
            <div class="hint">
                <strong>SSH:</strong> For Linux/Unix systems. 
                <br>• Raspberry Pi: user <code>pi</code>, port <code>22</code>
                <br>• Ubuntu/Debian: user <code>ubuntu</code> or <code>admin</code>
                <br>• Routers: user <code>admin</code> or <code>root</code>
            </div>
        `,
        'ftp': `
            <div class="hint">
                <strong>FTP:</strong> For file transfer.
                <br>• Anonymous access: user <code>anonymous</code>, password empty
                <br>• NAS devices: usually <code>admin</code> or <code>guest</code>
            </div>
        `,
        'telnet': `
            <div class="hint">
                <strong>Telnet:</strong> For older devices and routers.
                <br>• Routers: <code>admin/admin</code>, <code>root/admin</code>
                <br>⚠️ Not secure, prefer SSH
            </div>
        `,
        'http': `
            <div class="hint">
                <strong>HTTP Auth:</strong> For web interface access.
                <br>• Routers: <code>admin/admin</code>, <code>admin/password</code>
                <br>• IP Cameras: <code>admin/admin</code>, <code>admin/123456</code>
                <br>• IoT Devices: <code>admin</code> or device-specific
            </div>
        `,
        'snmp': `
            <div class="hint">
                <strong>SNMP:</strong> For system monitoring.
                <br>• Community String: usually <code>public</code> (in username field)
                <br>• SNMP v3 requires username and password
                <br>• Port: usually <code>161</code>
            </div>
        `,
        'api': `
            <div class="hint">
                <strong>API Token:</strong> For REST API access.
                <br>• Enter token in Password field
                <br>• Username usually not required
                <br>• Add API endpoints in Additional Info
            </div>
        `
    };
    
    hintsDiv.innerHTML = hints[accessType] || '';
}

async function testEnhancedAccess() {
    if (!currentEnhancedEditingIp) return;
    
    const accessData = {
        ip: currentEnhancedEditingIp,
        access_type: document.getElementById('enhancedAccessType').value,
        port: document.getElementById('enhancedAccessPort').value,
        username: document.getElementById('enhancedAccessUsername').value,
        password: document.getElementById('enhancedAccessPassword').value
    };
    
    if (!accessData.username || !accessData.password) {
        showToast(t('username_password_required'), 'error');
        return;
    }
    
    showToast(t('connection_test_starting'), 'info');
    
    try {
        const response = await fetch(`/test_device_access/${currentEnhancedEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast('✅ ' + t('connection_successful'), 'success');
        } else {
            showToast(`❌ ${t('connection_failed')}: ${result.error || t('unknown_error')}`, 'error');
        }
    } catch (error) {
        showToast(`❌ ${t('test_error')}: ${error.message}`, 'error');
    }
}

async function saveEnhancedAccess() {
    if (!currentEnhancedEditingIp) return;
    
    const accessData = {
        ip: currentEnhancedEditingIp,
        access_type: document.getElementById('enhancedAccessType').value,
        port: document.getElementById('enhancedAccessPort').value,
        username: document.getElementById('enhancedAccessUsername').value,
        password: document.getElementById('enhancedAccessPassword').value,
        notes: document.getElementById('enhancedAccessNotes').value
    };
    
    if (!accessData.username) {
        showToast(t('username_required'), 'error');
        return;
    }
    
    showToast(t('access_info_saving'), 'info');
    
    try {
        const response = await fetch('/save_device_credentials', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            showToast('✅ ' + t('access_info_saved'), 'success');
        } else {
            showToast(`❌ ${t('save_failed')}: ${result.error || t('unknown_error')}`, 'error');
        }
    } catch (error) {
        showToast(`❌ ${t('save_error')}: ${error.message}`, 'error');
    }
}


async function saveEnhancedDevice() {
    if (!currentEnhancedEditingIp) return;

    const device = devices.find(d => d.ip === currentEnhancedEditingIp);
    if (!device) return;

    // Collect data from all tabs
    const deviceData = {
        ip: document.getElementById('enhancedEditIpAddress').value,
        mac: document.getElementById('enhancedEditMacAddress').value,
        alias: document.getElementById('enhancedEditAlias').value,
        hostname: document.getElementById('enhancedEditHostname').value,
        vendor: document.getElementById('enhancedEditVendor').value,
        device_type: document.getElementById('enhancedEditDeviceType').value,
        notes: document.getElementById('enhancedEditNotes').value,
        open_ports: device.open_ports || []
    };

    try {
        const response = await fetch(`/update_device/${currentEnhancedEditingIp}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(deviceData)
        });

        const result = await response.json();

        if (response.ok) {
            showToast(t('device_updated_success'), 'success');
            closeEnhancedEditModal();
            await loadDevices(); // Reload devices
        } else {
            showToast(t('update_error') + ': ' + result.error, 'error');
        }
    } catch (error) {
        showToast(t('connection_error') + ': ' + error.message, 'error');
    }
}
