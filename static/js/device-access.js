// Device Access Management

let currentAccessDevice = null;

// Modal open function
function openDeviceAccessModal(ip) {
    currentAccessDevice = ip;
    document.getElementById('accessDeviceIP').value = ip;
    document.getElementById('deviceAccessModal').style.display = 'block';
    
    // Load existing access info
    loadExistingAccessInfo(ip);
    updateAccessForm();
}

// Modal close function
function closeDeviceAccessModal() {
    document.getElementById('deviceAccessModal').style.display = 'none';
    currentAccessDevice = null;
    clearAccessForm();
}

// Update form based on access type
function updateAccessForm() {
    const accessType = document.getElementById('accessType').value;
    const hintsDiv = document.getElementById('accessHints');
    
    // Auto set port
    const portField = document.getElementById('accessPort');
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
    
    // Update hints
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
                <br>• Anonymous access: user <code>anonymous</code>, empty password
                <br>• NAS devices: usually <code>admin</code> or <code>guest</code>
            </div>
        `,
        'telnet': `
            <div class="hint">
                <strong>Telnet:</strong> For legacy devices and routers.
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
                <br>• Community String: usually <code>public</code> (enter in username field)
                <br>• For SNMP v3, username and password required
                <br>• Port: usually <code>161</code>
            </div>
        `,
        'api': `
            <div class="hint">
                <strong>API Token:</strong> For REST API access.
                <br>• Enter token in the Password field
                <br>• Username usually not required
                <br>• Add API endpoints to Additional Info
            </div>
        `
    };
    
    hintsDiv.innerHTML = hints[accessType] || '';
}

// Clear form
function clearAccessForm() {
    document.getElementById('accessUsername').value = '';
    document.getElementById('accessPassword').value = '';
    document.getElementById('accessPort').value = '';
    document.getElementById('accessNotes').value = '';
    document.getElementById('accessType').value = 'ssh';
}

// Load existing access info
async function loadExistingAccessInfo(ip) {
    try {
        console.log(`Loading existing access info for ${ip}`);
        const response = await fetch(`/device_access/${ip}`);
        console.log(`Response status: ${response.status}`);
        
        if (response.ok) {
            const accessInfo = await response.json();
            console.log(`Access info received:`, accessInfo);
            
            if (accessInfo && Object.keys(accessInfo).length > 0) {
                // Load first access type
                const firstType = Object.keys(accessInfo)[0];
                const firstAccess = accessInfo[firstType];
                
                document.getElementById('accessType').value = firstType;
                document.getElementById('accessUsername').value = firstAccess.username || '';
                
                // Hide password - show placeholder if exists
                const passwordField = document.getElementById('accessPassword');
                if (firstAccess.has_password) {
                    passwordField.placeholder = '••••••••';
                    passwordField.value = '';
                    passwordField.setAttribute('data-has-existing', 'true');
                } else {
                    passwordField.placeholder = 'Enter password';
                    passwordField.value = '';
                    passwordField.removeAttribute('data-has-existing');
                }
                
                document.getElementById('accessPort').value = firstAccess.port || '';
                document.getElementById('accessNotes').value = 
                    JSON.stringify(firstAccess.additional_info || {}, null, 2);
                
                updateAccessForm();
            }
        }
    } catch (error) {
        console.error('Error loading access info:', error);
    }
}

// Save device access info
async function saveDeviceAccess() {
    if (!currentAccessDevice) {
        showToast('Invalid device!', 'error');
        return;
    }
    
    console.log(`Saving device access for ${currentAccessDevice}`);
    
    const passwordField = document.getElementById('accessPassword');
    const accessData = {
        access_type: document.getElementById('accessType').value,
        username: document.getElementById('accessUsername').value,
        password: passwordField.value,
        port: document.getElementById('accessPort').value || null,
        additional_info: {}
    };
    
    // If password field is empty and there is an existing password, do not update password
    if (!passwordField.value && passwordField.getAttribute('data-has-existing') === 'true') {
        accessData.keep_existing_password = true;
        console.log('Keeping existing password');
    }
    
    console.log('Access data to save:', { ...accessData, password: accessData.password ? '***HIDDEN***' : 'EMPTY' });
    
    // Parse additional info
    const notes = document.getElementById('accessNotes').value.trim();
    if (notes) {
        try {
            accessData.additional_info = JSON.parse(notes);
        } catch (e) {
            accessData.additional_info = { notes: notes };
        }
    }
    
    try {
        console.log('Sending POST request to save credentials...');
        const response = await fetch(`/device_access/${currentAccessDevice}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        console.log(`Save response status: ${response.status}`);
        const result = await response.json();
        console.log('Save response result:', result);
        
        if (response.ok) {
            showToast('Access information saved!', 'success');
            console.log('Credentials saved successfully');
        } else {
            console.error('Save error:', result.error);
            showToast(`Save error: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Save connection error:', error);
        showToast(`Connection error: ${error.message}`, 'error');
    }
}

// Test device access
async function testDeviceAccess() {
    if (!currentAccessDevice) {
        showToast('Invalid device!', 'error');
        return;
    }
    
    const passwordField = document.getElementById('accessPassword');
    const accessData = {
        access_type: document.getElementById('accessType').value,
        username: document.getElementById('accessUsername').value,
        password: passwordField.value,
        port: document.getElementById('accessPort').value || null
    };
    
    // If password field is empty and there is an existing password, use stored credentials
    if (!passwordField.value && passwordField.getAttribute('data-has-existing') === 'true') {
        accessData.use_stored_credentials = true;
        console.log('Using stored credentials for test');
    }
    
    console.log('Test access data:', { ...accessData, password: accessData.password ? '***HIDDEN***' : 'EMPTY' });
    
    // Disable test button
    const testBtn = event.target;
    const originalText = testBtn.innerHTML;
    testBtn.disabled = true;
    testBtn.innerHTML = '🔄 Testing...';
    
    try {
        console.log('Sending test request...');
        const response = await fetch(`/test_device_access/${currentAccessDevice}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(accessData)
        });
        
        console.log(`Test response status: ${response.status}`);
        const result = await response.json();
        console.log('Test response result:', result);
        
        if (response.ok) {
            if (result.success) {
                console.log('Test successful:', result);
                showToast(`✅ Access successful! ${result.details || ''}`, 'success');
            } else {
                console.error('Test failed:', result.error);
                showToast(`❌ Access failed: ${result.error}`, 'error');
            }
        } else {
            console.error('Test error response:', result.error);
            showToast(`Test error: ${result.error}`, 'error');
        }
    } catch (error) {
        console.error('Test connection error:', error);
        showToast(`Connection error: ${error.message}`, 'error');
    } finally {
        // Re-enable test button
        testBtn.disabled = false;
        testBtn.innerHTML = originalText;
    }
}

// Run enhanced analysis - now opens Detailed Device Analysis page
async function runEnhancedAnalysis() {
    if (!currentAccessDevice) {
        showToast('Invalid device!', 'error');
        return;
    }
    
    // Save IP (before closing modal)
    const deviceIP = currentAccessDevice;
    
    // Save access info first
    await saveDeviceAccess();
    
    showToast('Access information saved! Opening Detailed Device Analysis page...', 'success');
    
    // Close modal
    closeDeviceAccessModal();
    
    // Use saved IP to open Detailed Device Analysis page
    openSingleDeviceAnalysisPage(deviceIP);
}

// Open Detailed Device Analysis page
function openSingleDeviceAnalysisPage(ip) {
    // Create a new page or show in current page
    const analysisUrl = `/single_device_analysis/${ip}`;
    
    // If single device analysis page does not exist, show as modal
    showSingleDeviceAnalysisModal(ip);
}

// Global variables - multi-analysis support
let activeAnalysisSessions = new Map(); // IP -> {isMinimized, type, toasterId}
let analysisToasters = new Map(); // Minimized analysis toasters
let isAnalysisMinimized = false; // Analysis modal minimized state
let analysisToasterCount = 0;

// Unified modal to start bulk analysis
async function startUnifiedBulkAnalysis(sessionKey) {
    window.unifiedAnalysisMode = true;
    
    // Update UI state
    updateUnifiedAnalysisButtons(sessionKey, true);
    
    try {
        // Call function from main.js
        await startBulkAnalysisActual();
    } catch (error) {
        updateUnifiedAnalysisButtons(sessionKey, false);
    }
}

// Update Unified modal button states
function updateUnifiedAnalysisButtons(sessionKey, isRunning) {
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
    
    // Show verbose logs section
    const verboseSection = document.getElementById('verboseLogsSection');
    if (verboseSection && isRunning) {
        verboseSection.style.display = 'block';
    }
}

// Show Unified Advanced Analysis modal
function showSingleDeviceAnalysisModal(ip) {
    showUnifiedAnalysisModal(ip, 'single');
}

// Show bulk analysis Unified modal
function showBulkAnalysisModal() {
    showUnifiedAnalysisModal(null, 'bulk');
}

// Unified Advanced Analysis Modal
function showUnifiedAnalysisModal(targetIP = null, analysisType = 'single') {
    // Multi-session support
    const sessionKey = analysisType === 'bulk' ? 'bulk' : targetIP;
    
    // If an analysis is already active, show that modal
    if (activeAnalysisSessions.has(sessionKey)) {
        const session = activeAnalysisSessions.get(sessionKey);
        if (session.isMinimized) {
            maximizeAnalysisModal(sessionKey);
        }
        return;
    }
    
    const isSingleDevice = analysisType === 'single';
    const title = isSingleDevice ? `🔬 Advanced Analysis - ${targetIP}` : '🔬 Bulk Advanced Analysis';
    const buttonText = isSingleDevice ? '🚀 Start Advanced Analysis' : '🚀 Start Bulk Advanced Analysis';
    const startFunction = isSingleDevice ? `startSingleDeviceAnalysis('${targetIP}')` : `startUnifiedBulkAnalysis('${sessionKey}')`;
    
    // Description text
    const descriptionText = isSingleDevice ? 
        `This analysis performs a comprehensive review on the device ${targetIP}. If access information is available, it collects detailed system information via SSH, FTP, HTTP, and SNMP protocols.` :
        'This analysis performs advanced scanning and analysis on all devices in the network. It collects comprehensive information for each device using available access information.';
    
    // Unique modal ID
    const modalId = `unifiedAnalysisModal_${sessionKey.replace(/\./g, '_')}`;
    
    // Save session
    activeAnalysisSessions.set(sessionKey, {
        isMinimized: false,
        type: analysisType,
        modalId: modalId,
        targetIP: targetIP
    });
    
    // Create modal
    const modalHtml = `
        <div id="${modalId}" class="modal" style="display: block;">
            <div class="modal-content" style="width: 95%; max-width: 1400px; max-height: 90vh; overflow-y: auto;">
                <div class="modal-header">
                    <h2>${title}</h2>
                    <div class="modal-controls">
                        <span class="close" onclick="handleModalClose('${sessionKey}')">&times;</span>
                    </div>
                </div>
                <div class="modal-body">
                    <!-- Description Section -->
                    <div class="analysis-description" style="background: #f8f9fa; padding: 15px; border-radius: 8px; margin-bottom: 20px; border-left: 4px solid #007bff;">
                        <h4 style="margin: 0 0 10px 0; color: #007bff;">📋 About Advanced Analysis</h4>
                        <p style="margin: 0; color: #6c757d; line-height: 1.5;">${descriptionText}</p>
                        <div style="margin-top: 10px; font-size: 0.9em;">
                            <strong>Actions to be performed:</strong>
                            <ul style="margin: 5px 0 0 20px; color: #6c757d;">
                                <li>🔍 Port scanning and service detection</li>
                                <li>🔐 System analysis with access information</li>
                                <li>💻 Hardware and software information collection</li>
                                <li>🛡️ Security status assessment</li>
                                <li>📊 Comprehensive report generation</li>
                            </ul>
                        </div>
                    </div>

                    <div id="unifiedAnalysisContent">
                        <div class="analysis-section">
                            <button id="startBtn_${sessionKey.replace(/\./g, '_')}" onclick="${startFunction}" class="btn btn-primary">
                                ${buttonText}
                            </button>
                            <button id="stopBtn_${sessionKey.replace(/\./g, '_')}" onclick="stopAnalysis('${sessionKey}')" 
                                class="btn btn-danger" style="display: none; margin-left: 10px;">
                                🛑 Stop Analysis
                            </button>
                            <button id="minimizeBtn_${sessionKey.replace(/\./g, '_')}" onclick="minimizeAnalysisModal('${sessionKey}')" 
                                class="btn btn-secondary" style="display: none; margin-left: 10px;">
                                📦 Minimize
                            </button>
                            <div id="analysisProgress" style="display: none; margin-top: 15px;">
                                <div class="progress-bar" style="background: #e9ecef; height: 25px; border-radius: 5px; overflow: hidden;">
                                    <div id="progressBar" style="width: 0%; background: linear-gradient(90deg, #007bff, #0056b3); height: 100%; transition: width 0.5s; color: white; text-align: center; line-height: 25px; font-weight: bold;"></div>
                                </div>
                                <div id="progressText" style="margin-top: 10px; font-weight: bold;">Analysis starting...</div>
                            </div>
                        </div>
                        
                        <!-- Verbose Log Section -->
                        <div class="verbose-logs-section" id="verboseLogsSection" style="display: none; margin-top: 20px;">
                            <div style="border: 1px solid #ddd; border-radius: 5px; background: #f8f9fa;">
                                <div style="background: #e9ecef; padding: 10px; border-bottom: 1px solid #ddd; font-weight: bold;">
                                    📝 Detailed Analysis Logs (Real-time)
                                </div>
                                <div id="verboseLogs" style="height: 300px; overflow-y: auto; padding: 10px; font-family: 'Courier New', monospace; font-size: 12px; line-height: 1.4; background: #fff;">
                                    <!-- Verbose logs will appear here -->
                                </div>
                            </div>
                        </div>
                        
                        <div class="analysis-results" id="analysisResults" style="display: none; margin-top: 20px;">
                            <h3>Analysis Results</h3>
                            <div id="analysisResultsContent"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Add modal to page
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

// Handle modal close (minimize if active analysis exists)
function handleModalClose(sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) {
        closeUnifiedAnalysisModal(sessionKey);
        return;
    }
    
    // Check analysis state
    const modal = document.getElementById(session.modalId);
    if (!modal) {
        closeUnifiedAnalysisModal(sessionKey);
        return;
    }
    
    // Check if progress is shown
    const progressDiv = modal.querySelector('#analysisProgress');
    const isAnalysisActive = progressDiv && progressDiv.style.display !== 'none';
    
    if (isAnalysisActive) {
        // Minimize if active analysis exists
        minimizeAnalysisModal(sessionKey);
    } else {
        // Close normally if no analysis
        closeUnifiedAnalysisModal(sessionKey);
    }
}

// Close Unified Analysis modal (backward compatibility)
function closeSingleDeviceAnalysisModal() {
    // Fallback for old system
    const oldModal = document.getElementById('singleDeviceAnalysisModal');
    if (oldModal) {
        oldModal.remove();
        return;
    }
    
    // New system - close first session
    if (activeAnalysisSessions.size > 0) {
        const firstKey = activeAnalysisSessions.keys().next().value;
        closeUnifiedAnalysisModal(firstKey);
    }
}

// Close Unified Analysis modal
function closeUnifiedAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Fallback for old system
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        if (modal) {
            modal.remove();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (modal) {
        modal.remove();
    }
    
    // Clear related toaster
    const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
    if (toaster) {
        toaster.remove();
    }
    
    // Delete session
    activeAnalysisSessions.delete(sessionKey);
}

// Minimize modal
function minimizeAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Fallback for old system
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        if (modal) {
            modal.style.display = 'none';
            showAnalysisToaster();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (modal) {
        modal.style.display = 'none';
        session.isMinimized = true;
        isAnalysisMinimized = true;
        showAnalysisToaster(sessionKey);
    }
}

// Maximize modal
function maximizeAnalysisModal(sessionKey) {
    if (!sessionKey) {
        // Fallback for old system
        const modal = document.getElementById('unifiedAnalysisModal') || document.getElementById('singleDeviceAnalysisModal');
        const toaster = document.getElementById('analysisToaster');
        
        if (modal) {
            modal.style.display = 'block';
        }
        
        if (toaster) {
            toaster.remove();
        }
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) {
        // Recreate if session does not exist
        restoreSessionFromServer(sessionKey);
        return;
    }
    
    const modal = document.getElementById(session.modalId);
    const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
    
    if (modal) {
        modal.style.display = 'block';
        session.isMinimized = false;
        isAnalysisMinimized = false;
        
        // Restore UI state if analysis is active
        if (typeof bulkAnalysisRunning !== 'undefined' && bulkAnalysisRunning) {
            updateUnifiedAnalysisButtons(sessionKey, true);
            
            // Show verbose logs section
            const verboseSection = document.getElementById('verboseLogsSection');
            if (verboseSection) {
                verboseSection.style.display = 'block';
            }
        } else if (sessionKey === 'bulk') {
            // Check server state for bulk analysis
            checkBulkAnalysisStatusAndRestoreUI(sessionKey);
        }
        
        // Load analysis results from temp file
        loadAnalysisFromTemp(sessionKey);
        
        // Update modal buttons based on active analysis state
        updateModalButtonsForActiveAnalysis(sessionKey);
    }
    
    if (toaster) {
        toaster.remove();
    }
}

// Restore session from server
async function restoreSessionFromServer(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (activeAnalyses[sessionKey]) {
            const analysisInfo = activeAnalyses[sessionKey];
            
            if (analysisInfo.type === 'single') {
                await restoreSingleDeviceAnalysis(sessionKey, analysisInfo);
            } else if (analysisInfo.type === 'bulk') {
                await restoreBulkAnalysis(analysisInfo);
            }
            
            // Show modal
            const session = activeAnalysisSessions.get(sessionKey);
            if (session) {
                const modal = document.getElementById(session.modalId);
                if (modal) {
                    modal.style.display = 'block';
                    session.isMinimized = false;
                }
            }
        }
    } catch (error) {
        console.error('Session restore error:', error);
        showToast('❌ Failed to restore analysis session', 'error');
    }
}

// Load analysis results from temp file
async function loadAnalysisFromTemp(sessionKey) {
    try {
        const response = await fetch(`/load_analysis_temp/${sessionKey}`);
        if (response.ok) {
            const tempData = await response.json();
            const session = activeAnalysisSessions.get(sessionKey);
            
            if (session && tempData.analysis_results) {
                const modal = document.getElementById(session.modalId);
                const resultsDiv = modal.querySelector('.analysis-results');
                
                if (resultsDiv && tempData.analysis_results) {
                    resultsDiv.innerHTML = tempData.analysis_results;
                }
                
                // Update progress
                if (tempData.progress !== undefined) {
                    const progressBar = modal.querySelector('.progress-bar-fill');
                    const progressText = modal.querySelector('.progress-text');
                    
                    if (progressBar) {
                        progressBar.style.width = tempData.progress + '%';
                    }
                    
                    if (progressText && tempData.message) {
                        progressText.textContent = tempData.message;
                    }
                }
            }
        }
    } catch (error) {
        console.warn('Temp file load error:', error);
    }
}

// Update modal buttons based on active analysis state
async function updateModalButtonsForActiveAnalysis(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        const isActive = activeAnalyses[sessionKey] && activeAnalyses[sessionKey].status === 'analyzing';
        
        const session = activeAnalysisSessions.get(sessionKey);
        if (!session) return;
        
        const modal = document.getElementById(session.modalId);
        if (!modal) return;
        
        // Find buttons
        const startBtn = modal.querySelector('[onclick*="startSingleDeviceAnalysis"], [onclick*="startBulkAnalysis"]');
        const stopBtn = modal.querySelector('[onclick*="stopAnalysis"]');
        const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
        
        if (isActive) {
            // If analysis is active
            if (startBtn) {
                startBtn.disabled = true;
                startBtn.style.opacity = '0.5';
                startBtn.style.cursor = 'not-allowed';
            }
            
            if (stopBtn) {
                stopBtn.disabled = false;
                stopBtn.style.opacity = '1';
                stopBtn.style.cursor = 'pointer';
                stopBtn.style.display = 'inline-block';
            }
            
            if (minimizeBtn) {
                minimizeBtn.disabled = false;
                minimizeBtn.style.display = 'inline-block';
            }
        } else {
            // If no active analysis
            if (startBtn) {
                startBtn.disabled = false;
                startBtn.style.opacity = '1';
                startBtn.style.cursor = 'pointer';
            }
            
            if (stopBtn) {
                stopBtn.style.display = 'none';
            }
            
            if (minimizeBtn) {
                minimizeBtn.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Button update error:', error);
    }
}

// Show analysis toaster
function showAnalysisToaster(sessionKey) {
    if (!sessionKey) {
        // Fallback for old system
        const existingToaster = document.getElementById('analysisToaster');
        if (existingToaster) {
            existingToaster.remove();
        }
        
        const toasterHtml = `
            <div id="analysisToaster" style="
                position: fixed;
                bottom: 20px;
                right: 20px;
                width: 300px;
                background: linear-gradient(135deg, #007bff, #0056b3);
                color: white;
                padding: 15px;
                border-radius: 10px;
                box-shadow: 0 4px 20px rgba(0,0,0,0.3);
                z-index: 10000;
                cursor: pointer;
                transition: all 0.3s ease;
            " onclick="maximizeAnalysisModal()">
                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                    <div style="font-weight: bold; flex: 1;">
                        🔬 Analysis Ongoing
                    </div>
                    <div onclick="event.stopPropagation(); closeSingleDeviceAnalysisModal();" style="
                        background: rgba(255,255,255,0.2);
                        border-radius: 50%;
                        width: 20px;
                        height: 20px;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 12px;
                        cursor: pointer;
                    ">&times;</div>
                </div>
                <div id="toasterProgressText" style="font-size: 12px; opacity: 0.9;">
                    Analysis is ongoing...
                </div>
                <div style="background: rgba(255,255,255,0.2); height: 4px; border-radius: 2px; margin-top: 8px; overflow: hidden;">
                    <div id="toasterProgressBar" style="background: white; height: 100%; width: 0%; transition: width 0.5s;"></div>
                </div>
            </div>
        `;
        
        document.body.insertAdjacentHTML('beforeend', toasterHtml);
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const toasterId = `analysisToaster_${sessionKey.replace(/\./g, '_')}`;
    const existingToaster = document.getElementById(toasterId);
    if (existingToaster) {
        existingToaster.remove();
    }
    
    // Calculate toaster position (for multiple toasters)
    const toasterPosition = calculateToasterPosition();
    const displayName = session.type === 'bulk' ? 'Bulk Analysis' : `Analysis - ${session.targetIP}`;
    
    const toasterHtml = `
        <div id="${toasterId}" style="
            position: fixed;
            bottom: ${toasterPosition.bottom}px;
            right: ${toasterPosition.right}px;
            width: 280px;
            background: linear-gradient(135deg, #007bff, #0056b3);
            color: white;
            padding: 12px;
            border-radius: 8px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 10000;
            cursor: pointer;
            transition: all 0.3s ease;
            font-size: 13px;
        " onclick="maximizeAnalysisModal('${sessionKey}')">
            <div style="display: flex; align-items: center; margin-bottom: 6px;">
                <div style="font-weight: bold; flex: 1;">
                    🔬 ${displayName}
                </div>
                <div onclick="event.stopPropagation(); handleToasterClose('${sessionKey}');" style="
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    width: 18px;
                    height: 18px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 11px;
                    cursor: pointer;
                ">&times;</div>
            </div>
            <div id="toasterProgressText_${sessionKey.replace(/\./g, '_')}" style="font-size: 11px; opacity: 0.9;">
                Analysis is ongoing...
            </div>
            <div style="background: rgba(255,255,255,0.2); height: 3px; border-radius: 2px; margin-top: 6px; overflow: hidden;">
                <div id="toasterProgressBar_${sessionKey.replace(/\./g, '_')}" style="background: white; height: 100%; width: 0%; transition: width 0.5s;"></div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', toasterHtml);
}

// Calculate toaster position (for multiple toasters)
function calculateToasterPosition() {
    const existingToasters = document.querySelectorAll('[id^="analysisToaster_"]');
    const baseBottom = 20;
    const baseRight = 20;
    const toasterHeight = 80; // Approximate toaster height
    const margin = 10;
    
    return {
        bottom: baseBottom + (existingToasters.length * (toasterHeight + margin)),
        right: baseRight
    };
}

// Update toaster progress
function updateToasterProgress(sessionKey, progressPercent, message) {
    if (!sessionKey) {
        console.warn('updateToasterProgress called without sessionKey');
        return;
    }
    
    const toasterProgressBar = document.getElementById(`toasterProgressBar_${sessionKey.replace(/\./g, '_')}`);
    const toasterProgressText = document.getElementById(`toasterProgressText_${sessionKey.replace(/\./g, '_')}`);
    
    if (toasterProgressBar) {
        toasterProgressBar.style.width = progressPercent + '%';
    }
    
    if (toasterProgressText) {
        toasterProgressText.textContent = message;
    }
}

// Handle toaster close - clear temp file if active analysis exists
function handleToasterClose(sessionKey) {
    // Check active analysis state
    fetch('/get_active_analyses')
        .then(response => response.json())
        .then(activeAnalyses => {
            const isActive = activeAnalyses[sessionKey] && activeAnalyses[sessionKey].status === 'analyzing';
            
            if (isActive) {
                // If active analysis exists, keep toaster open
                console.log('Active analysis ongoing, toaster will remain open');
                showToast('ℹ️ Analysis ongoing, toaster will remain open', 'info');
                return;
            } else {
                // Close toaster if analysis is finished
                const toaster = document.getElementById(`analysisToaster_${sessionKey.replace(/\./g, '_')}`);
                if (toaster) {
                    toaster.remove();
                }
                
                // Clear session
                if (activeAnalysisSessions.has(sessionKey)) {
                    activeAnalysisSessions.delete(sessionKey);
                }
                
                // Clear temp file
                fetch(`/clear_analysis_temp/${sessionKey}`, { method: 'POST' })
                    .catch(error => console.warn('Temp file clear error:', error));
            }
        })
        .catch(error => {
            console.error('Active analysis check error:', error);
        });
}

// Save analysis data to temp file
async function saveAnalysisToTemp(sessionKey, analysisData) {
    try {
        const response = await fetch('/save_analysis_temp', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                session_key: sessionKey,
                analysis_data: analysisData
            })
        });
        
        if (!response.ok) {
            console.warn('Temp file save error:', response.statusText);
        }
    } catch (error) {
        console.warn('Temp file save error:', error);
    }
}

// Show analysis completed notification
function showAnalysisCompletedNotification() {
    const notificationHtml = `
        <div id="completedNotification" style="
            position: fixed;
            top: 20px;
            right: 20px;
            width: 350px;
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.3);
            z-index: 10001;
            animation: slideInRight 0.5s ease;
        ">
            <div style="display: flex; align-items: center; margin-bottom: 10px;">
                <div style="font-size: 24px; margin-right: 10px;">✅</div>
                <div style="font-weight: bold; flex: 1;">
                    Analysis Completed!
                </div>
                <div onclick="document.getElementById('completedNotification').remove();" style="
                    background: rgba(255,255,255,0.2);
                    border-radius: 50%;
                    width: 24px;
                    height: 24px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    cursor: pointer;
                ">&times;</div>
            </div>
            <div style="font-size: 14px; opacity: 0.9;">
                Detailed analysis for ${currentAnalysisIP} has been successfully completed.
            </div>
            <div style="margin-top: 15px;">
                <button onclick="maximizeAnalysisModal(); document.getElementById('completedNotification').remove();" 
                        style="background: rgba(255,255,255,0.2); border: none; color: white; padding: 8px 16px; border-radius: 5px; cursor: pointer;">
                    📊 View Results
                </button>
            </div>
        </div>
        
        <style>
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        </style>
    `;
    
    document.body.insertAdjacentHTML('beforeend', notificationHtml);
    
    // Auto close after 10 seconds
    setTimeout(() => {
        const notification = document.getElementById('completedNotification');
        if (notification) {
            notification.remove();
        }
    }, 10000);
}

// Start bulk analysis
async function startBulkAnalysis() {
    const sessionKey = 'bulk';
    
    // Check if modal exists, create if not
    if (!activeAnalysisSessions.has(sessionKey)) {
        console.error('Bulk analysis modal not found. Creating modal first...');
        showUnifiedAnalysisModal(null, 'bulk');
        // Short delay after modal creation
        await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    
    const progressDiv = modal.querySelector('#analysisProgress');
    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');
    const resultsDiv = modal.querySelector('#analysisResults');
    const verboseLogsSection = modal.querySelector('#verboseLogsSection');
    const verboseLogs = modal.querySelector('#verboseLogs');
    const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
    
    // Check if elements exist
    if (!progressDiv || !progressBar || !progressText || !resultsDiv || !verboseLogsSection || !verboseLogs || !minimizeBtn) {
        console.error('Required modal elements not found:', {
            progressDiv: !!progressDiv,
            progressBar: !!progressBar,
            progressText: !!progressText,
            resultsDiv: !!resultsDiv,
            verboseLogsSection: !!verboseLogsSection,
            verboseLogs: !!verboseLogs,
            minimizeBtn: !!minimizeBtn
        });
        alert('Modal elements not found. Please refresh the page.');
        return;
    }
    
    // Show progress
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    verboseLogsSection.style.display = 'block';
    minimizeBtn.style.display = 'inline-block';
    
    // Clear verbose logs
    verboseLogs.innerHTML = '';
    
    try {
        addVerboseLog('🚀 Starting bulk advanced analysis...');
        
        // Start bulk analysis
        const response = await fetch('/detailed_analysis');
        const result = await response.json();
        
        if (response.ok) {
            progressText.textContent = 'Bulk analysis started, monitoring progress...';
            progressBar.style.width = '5%';
            progressBar.textContent = '5%';
            addVerboseLog('✅ Bulk analysis successfully started');
            addVerboseLog('🔄 Starting real-time monitoring...');
            
            // Monitor progress
            monitorBulkAnalysisProgress();
            
        } else {
            progressText.textContent = `Analysis error: ${result.error}`;
            addVerboseLog(`❌ Analysis start error: ${result.error}`);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Connection error: ${error.message}`;
        addVerboseLog(`❌ Connection error: ${error.message}`);
        progressDiv.style.display = 'none';
    }
}

// Monitor bulk analysis progress
function monitorBulkAnalysisProgress() {
    const progressBar = document.getElementById('progressBar');
    const progressText = document.getElementById('progressText');
    const resultsDiv = document.getElementById('analysisResults');
    const resultsContent = document.getElementById('analysisResultsContent');
    
    let progressPercent = 5;
    let lastMessage = '';
    
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch('/detailed_analysis_status');
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                progressPercent = 100;
                progressBar.style.width = '100%';
                progressBar.textContent = '100%';
                progressText.textContent = 'Bulk analysis completed!';
                
                addVerboseLog('✅ Bulk analysis successfully completed!');
                addVerboseLog('📊 Preparing results...');
                
                // Update toaster progress
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', 100, 'Bulk analysis completed!');
                }
                
                // Show completed notification
                showAnalysisCompletedNotification();
                
                // Show results
                setTimeout(() => {
                    document.getElementById('analysisProgress').style.display = 'none';
                    resultsDiv.style.display = 'block';
                    resultsContent.innerHTML = `
                        <div class="analysis-summary">
                            <h4>🎉 Bulk Advanced Analysis Completed</h4>
                            <p>Advanced analysis for all devices has been successfully completed. Refresh the device list to see updated information.</p>
                            <button onclick="if(typeof loadDevices === 'function') loadDevices(true); else window.location.reload();" class="btn btn-success">
                                🔄 Refresh Device List
                            </button>
                        </div>
                    `;
                }, 1000);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                progressText.textContent = `Analysis error: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'ERROR';
                
                addVerboseLog(`❌ Analysis error: ${status.message}`);
                
                // Update toaster
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', 0, 'Analysis error!');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analysis ongoing...';
                progressText.textContent = currentMessage;
                
                // Add only new messages to verbose log
                if (currentMessage !== lastMessage) {
                    addVerboseLog(`🔄 ${currentMessage}`);
                    lastMessage = currentMessage;
                }
                
                // Increment progress (max up to 90%)
                if (progressPercent < 90) {
                    progressPercent += 3;
                    progressBar.style.width = progressPercent + '%';
                    progressBar.textContent = progressPercent + '%';
                }
                
                // Update toaster progress
                if (isAnalysisMinimized) {
                    updateToasterProgress('bulk', progressPercent, currentMessage);
                }
                
                // Save to temp file
                saveAnalysisToTemp('bulk', {
                    progress: progressPercent,
                    message: currentMessage,
                    status: status.status,
                    analysis_results: resultsContent ? resultsContent.innerHTML : '',
                    timestamp: new Date().toISOString()
                });
            }
        } catch (error) {
            console.error('Bulk analysis status check error:', error);
            addVerboseLog(`⚠️ Status check error: ${error.message}`);
        }
    }, 2000); // Check every 2 seconds
}

// Start single device analysis
async function startSingleDeviceAnalysis(ip) {
    const sessionKey = ip;
    
    // Check session
    if (!activeAnalysisSessions.has(sessionKey)) {
        console.error('Single device analysis session not found for:', ip);
        return;
    }
    
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    
    const progressDiv = modal.querySelector('#analysisProgress');
    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');
    const resultsDiv = modal.querySelector('#analysisResults');
    const verboseLogsSection = modal.querySelector('#verboseLogsSection');
    const verboseLogs = modal.querySelector('#verboseLogs');
    const minimizeBtn = modal.querySelector(`#minimizeBtn_${sessionKey.replace(/\./g, '_')}`);
    
    // Show progress
    progressDiv.style.display = 'block';
    resultsDiv.style.display = 'none';
    verboseLogsSection.style.display = 'block';
    minimizeBtn.style.display = 'inline-block';
    
    // Clear verbose logs
    verboseLogs.innerHTML = '';
    
    // Update buttons
    updateAnalysisButtons(sessionKey, true);
    
    try {
        addVerboseLog('🚀 Starting detailed analysis...', sessionKey);
        addVerboseLog(`📡 Target device: ${ip}`, sessionKey);
        
        // Start enhanced analysis
        const response = await fetch(`/enhanced_analysis/${ip}`, {
            method: 'POST'
        });
        
        const result = await response.json();
        
        if (response.ok) {
            progressText.textContent = 'Analysis started, monitoring progress...';
            progressBar.textContent = '5%';
            addVerboseLog('✅ Analysis successfully started', sessionKey);
            addVerboseLog('🔄 Starting real-time monitoring...', sessionKey);
            
            // Monitor progress
            monitorSingleDeviceAnalysis(ip);
            
        } else {
            progressText.textContent = `Analysis error: ${result.error}`;
            addVerboseLog(`❌ Analysis start error: ${result.error}`, sessionKey);
            progressDiv.style.display = 'none';
        }
    } catch (error) {
        progressText.textContent = `Connection error: ${error.message}`;
        addVerboseLog(`❌ Connection error: ${error.message}`, sessionKey);
        progressDiv.style.display = 'none';
    }
}

// Update analysis buttons (start/stop)
function updateAnalysisButtons(sessionKey, isRunning) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    const modal = document.getElementById(session.modalId);
    if (!modal) return;
    
    const startBtn = modal.querySelector(`#startBtn_${sessionKey.replace(/\./g, '_')}`);
    const stopBtn = modal.querySelector(`#stopBtn_${sessionKey.replace(/\./g, '_')}`);
    
    if (startBtn && stopBtn) {
        if (isRunning) {
            startBtn.disabled = true;
            startBtn.style.opacity = '0.6';
            stopBtn.style.display = 'inline-block';
        } else {
            startBtn.disabled = false;
            startBtn.style.opacity = '1';
            stopBtn.style.display = 'none';
        }
    }
}

// Stop analysis
async function stopAnalysis(sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    if (!session) return;
    
    try {
        if (session.type === 'bulk') {
            // Stop bulk analysis
            const response = await fetch('/stop_bulk_analysis', {
                method: 'POST'
            });
            addVerboseLog('🛑 Bulk analysis stop request sent...', sessionKey);
        } else {
            // Stop single device analysis
            const response = await fetch(`/stop_enhanced_analysis/${session.targetIP}`, {
                method: 'POST'
            });
            addVerboseLog(`🛑 Stop request sent for ${session.targetIP} analysis...`, sessionKey);
        }
        
        // Update buttons
        updateAnalysisButtons(sessionKey, false);
        
        // Stop progress
        const modal = document.getElementById(session.modalId);
        const progressText = modal.querySelector('#progressText');
        if (progressText) {
            progressText.textContent = 'Analysis stopped.';
        }
        
        addVerboseLog('✅ Analysis successfully stopped', sessionKey);
        
    } catch (error) {
        addVerboseLog(`❌ Analysis stop error: ${error.message}`, sessionKey);
    }
}

// Add verbose log - Session-aware version
function addVerboseLog(message, sessionKey = null) {
    // If no session key, check active sessions
    if (!sessionKey && activeAnalysisSessions.size > 0) {
        // Use first active session
        sessionKey = activeAnalysisSessions.keys().next().value;
    }
    
    if (sessionKey && activeAnalysisSessions.has(sessionKey)) {
        const session = activeAnalysisSessions.get(sessionKey);
        const modal = document.getElementById(session.modalId);
        if (modal) {
            const verboseLogs = modal.querySelector('#verboseLogs');
            if (verboseLogs) {
                const timestamp = new Date().toLocaleTimeString();
                const logEntry = document.createElement('div');
                logEntry.style.marginBottom = '4px';
                logEntry.innerHTML = `<span style="color: #666;">[${timestamp}]</span> ${message}`;
                verboseLogs.appendChild(logEntry);
                verboseLogs.scrollTop = verboseLogs.scrollHeight;
            }
        }
    }
}

// Monitor single device analysis progress
function monitorSingleDeviceAnalysis(ip) {
    const sessionKey = ip;
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    
    const progressBar = modal.querySelector('#progressBar');
    const progressText = modal.querySelector('#progressText');
    const resultsDiv = modal.querySelector('#analysisResults');
    const resultsContent = modal.querySelector('#analysisResultsContent');
    
    let progressPercent = 5;
    let lastMessage = '';
    
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch(`/enhanced_analysis_status/${ip}`);
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                progressPercent = 100;
                progressBar.style.width = '100%';
                progressBar.textContent = '100%';
                progressText.textContent = 'Analysis completed!';
                
                addVerboseLog('✅ Analysis successfully completed!', sessionKey);
                addVerboseLog('📊 Loading results...', sessionKey);
                
                // Reset buttons
                updateAnalysisButtons(sessionKey, false);
                
                // Update toaster progress
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 100, 'Analysis completed!');
                }
                
                // Show completed notification
                showAnalysisCompletedNotification();
                
                // Show results
                setTimeout(() => {
                    modal.querySelector('#analysisProgress').style.display = 'none';
                    resultsDiv.style.display = 'block';
                    
                    // Reload and show device details
                    loadDeviceAnalysisResults(ip, sessionKey);
                }, 1000);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                progressText.textContent = `Analysis error: ${status.message}`;
                progressBar.style.backgroundColor = '#dc3545';
                progressBar.textContent = 'ERROR';
                
                addVerboseLog(`❌ Analysis error: ${status.message}`, sessionKey);
                
                // Reset buttons
                updateAnalysisButtons(sessionKey, false);
                
                // Update toaster
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 0, 'Analysis error!');
                }
                
            } else if (status.status === 'stopped') {
                clearInterval(checkInterval);
                progressText.textContent = 'Analysis stopped';
                progressBar.style.backgroundColor = '#6c757d';
                progressBar.textContent = 'STOPPED';
                
                addVerboseLog('🛑 Analysis stopped by user', sessionKey);
                
                // Reset buttons
                updateAnalysisButtons(sessionKey, false);
                
                // Update toaster
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, 0, 'Analysis stopped');
                }
                
            } else if (status.status === 'analyzing') {
                const currentMessage = status.message || 'Analysis ongoing...';
                progressText.textContent = currentMessage;
                
                // Add only new messages to verbose log
                if (currentMessage !== lastMessage) {
                    addVerboseLog(`🔄 ${currentMessage}`, sessionKey);
                    lastMessage = currentMessage;
                }
                
                // Use progress from backend, otherwise increment
                if (status.progress) {
                    progressPercent = Math.round(status.progress);
                    progressBar.style.width = progressPercent + '%';
                    progressBar.textContent = progressPercent + '%';
                } else {
                    // Fallback: manual increment (max up to 90%)
                    if (progressPercent < 90) {
                        progressPercent += 5;
                        progressBar.style.width = progressPercent + '%';
                        progressBar.textContent = progressPercent + '%';
                    }
                }
                
                // Update toaster progress
                if (session.isMinimized) {
                    updateToasterProgress(sessionKey, progressPercent, currentMessage);
                }
                
                // Save to temp file
                saveAnalysisToTemp(sessionKey, {
                    progress: progressPercent,
                    message: currentMessage,
                    status: status.status,
                    analysis_results: resultsContent ? resultsContent.innerHTML : '',
                    timestamp: new Date().toISOString()
                });
                
                // Extract analysis type from message and add to verbose log
                analyzeStatusMessage(currentMessage, sessionKey);
            }
        } catch (error) {
            console.error('Analysis status check error:', error);
            addVerboseLog(`⚠️ Status check error: ${error.message}`, sessionKey);
        }
    }, 2000); // Check every 2 seconds
}

// Analyze status message and add detailed info
function analyzeStatusMessage(message, sessionKey) {
    const verboseMessages = {
        'access information': '🔐 Checking device access information',
        'credential': '🔑 Processing credentials',
        'port scan': '🔌 Port scanning in progress',
        'ssh': '🖥️ SSH service analysis in progress',
        'web': '🌐 Scanning web services', 
        'snmp': '📊 Retrieving SNMP information',
        'raspberry': '🥧 Raspberry Pi hardware analysis',
        'analysis results': '💾 Saving results',
        'comprehensive': '🔍 Comprehensive system scan'
    };
    
    const lowerMessage = message.toLowerCase();
    for (const [keyword, verboseMsg] of Object.entries(verboseMessages)) {
        if (lowerMessage.includes(keyword)) {
            addVerboseLog(verboseMsg, sessionKey);
            break;
        }
    }
}

// Load and show device analysis results
async function loadDeviceAnalysisResults(ip, sessionKey) {
    const session = activeAnalysisSessions.get(sessionKey);
    const modal = document.getElementById(session.modalId);
    const resultsContent = modal.querySelector('#analysisResultsContent');
    
    try {
        const response = await fetch(`/device/${ip}`);
        const device = await response.json();
        
        if (response.ok && device) {
            const enhancedInfo = device.enhanced_comprehensive_info || device.enhanced_info || {};
            
            let resultsHtml = `
                <div class="device-analysis-summary">
                    <h4>${device.alias || device.hostname || ip}</h4>
                    <p><strong>IP:</strong> ${device.ip}</p>
                    <p><strong>MAC:</strong> ${device.mac || 'N/A'}</p>
                    <p><strong>Vendor:</strong> ${device.vendor || 'N/A'}</p>
                    <p><strong>Device Type:</strong> ${device.device_type || 'Unknown'}</p>
                    <p><strong>Status:</strong> ${device.status || 'N/A'}</p>
                </div>
            `;
            
            // Open ports
            if (device.open_ports && device.open_ports.length > 0) {
                resultsHtml += `
                    <div class="analysis-section">
                        <h4>🔌 Open Ports</h4>
                        <div class="ports-grid">
                `;
                
                device.open_ports.forEach(port => {
                    if (typeof port === 'object') {
                        resultsHtml += `
                            <div class="port-item">
                                <span class="port-number">${port.port}</span>
                                <span class="port-description">${port.description || port.service || 'Unknown'}</span>
                            </div>
                        `;
                    } else {
                        resultsHtml += `
                            <div class="port-item">
                                <span class="port-number">${port}</span>
                                <span class="port-description">Unknown Service</span>
                            </div>
                        `;
                    }
                });
                
                resultsHtml += `
                        </div>
                    </div>
                `;
            }
            
            // Enhanced info
            if (enhancedInfo && Object.keys(enhancedInfo).length > 0) {
                resultsHtml += `
                    <div class="analysis-section">
                        <h4>🔍 Advanced Analysis Information</h4>
                        <div class="enhanced-info">
                            <pre>${JSON.stringify(enhancedInfo, null, 2)}</pre>
                        </div>
                    </div>
                `;
            }
            
            resultsContent.innerHTML = resultsHtml;
        } else {
            resultsContent.innerHTML = '<p>Failed to load device information.</p>';
        }
    } catch (error) {
        resultsContent.innerHTML = `<p>Error: ${error.message}</p>`;
    }
}

// Monitor enhanced analysis progress
function monitorEnhancedAnalysis(ip) {
    const checkInterval = setInterval(async () => {
        try {
            const response = await fetch(`/enhanced_analysis_status/${ip}`);
            const status = await response.json();
            
            if (status.status === 'completed') {
                clearInterval(checkInterval);
                showToast(`🎉 Enhanced analysis for ${ip} completed!`, 'success');
                
                // Refresh device list
                await loadDevices(true);
                
            } else if (status.status === 'error') {
                clearInterval(checkInterval);
                showToast(`❌ Analysis error for ${ip}: ${status.message}`, 'error');
            } else if (status.status === 'analyzing') {
                // Show progress (optional)
                console.log(`${ip} is being analyzed: ${status.message}`);
            }
        } catch (error) {
            console.error('Enhanced analysis status check error:', error);
        }
    }, 3000); // Check every 3 seconds
}

// Add access button to device table
function addAccessButtonToDevice(deviceRow, ip) {
    const actionsCell = deviceRow.querySelector('.device-actions');
    if (actionsCell) {
        const accessBtn = document.createElement('button');
        accessBtn.className = 'btn btn-sm btn-info';
        accessBtn.innerHTML = '🔐';
        accessBtn.title = 'Access Information';
        accessBtn.onclick = () => openDeviceAccessModal(ip);
        
        actionsCell.appendChild(accessBtn);
    }
}

// Check bulk analysis status and restore UI
async function checkBulkAnalysisStatusAndRestoreUI(sessionKey) {
    try {
        const response = await fetch('/get_active_analyses');
        const activeAnalyses = await response.json();
        
        if (activeAnalyses.bulk && activeAnalyses.bulk.status === 'analyzing') {
            // Bulk analysis is ongoing on server, restore UI
            updateUnifiedAnalysisButtons(sessionKey, true);
            
            // Show verbose logs section
            const verboseSection = document.getElementById('verboseLogsSection');
            if (verboseSection) {
                verboseSection.style.display = 'block';
            }
            
            // Update global variable
            if (typeof bulkAnalysisRunning !== 'undefined') {
                window.bulkAnalysisRunning = true;
            }
            
            console.log('✅ Bulk analysis UI state restored from server state');
        } else {
            // Analysis not ongoing, normal UI
            updateUnifiedAnalysisButtons(sessionKey, false);
            console.log('ℹ️ Bulk analysis completed or stopped');
        }
    } catch (error) {
        console.error('Bulk analysis status check error:', error);
    }
}

// Close modal on outside click
window.addEventListener('click', function(event) {
    const modal = document.getElementById('deviceAccessModal');
    if (event.target === modal) {
        closeDeviceAccessModal();
    }
});

// Keyboard shortcuts
document.addEventListener('keydown', function(event) {
    if (event.key === 'Escape' && document.getElementById('deviceAccessModal').style.display === 'block') {
        closeDeviceAccessModal();
    }
});