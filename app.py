#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Scanner Web UI - Flask-based advanced web interface
Enhanced version with configuration management and additional features
"""

# Suppress warnings
import warnings
import os
import sys

# Suppress Cryptography deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="scapy")

# Suppress Scapy and network interface warnings
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# dotenv support for environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Flask and other imports
from flask import Flask, render_template, jsonify, request, send_from_directory, session, redirect, url_for
import threading
from datetime import datetime
from lan_scanner import LANScanner
from oui_manager import OUIManager
from docker_manager import docker_manager
from credential_manager import get_credential_manager
from version import get_version, get_version_info
from data_sanitizer import DataSanitizer
from unified_device_model import unified_model
from language_manager import language_manager, _, get_language_manager
import re
import requests
import csv
import json
import os

app = Flask(__name__)
# Use environment variable or generate a random secret key
app.secret_key = os.environ.get('FLASK_SECRET_KEY', os.urandom(24).hex())

# Disable caching for all requests (for development and translation updates)
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

@app.after_request
def after_request(response):
    """Add cache control headers to prevent caching issues"""
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Global variables
scanner = LANScanner()
oui_manager = OUIManager()
scan_progress = {"status": "idle", "message": "ready", "devices_found": 0}
scan_thread = None

# Background analysis tracking for global variables
background_analysis = {"status": "idle", "message": "ready"}
detailed_analysis_thread = None

# Enhanced analysis tracking
enhanced_analysis_status = {}
bulk_analysis_status = {}

# Secure credential manager
credential_manager = get_credential_manager()

# Template context processor for language support
@app.context_processor
def inject_language_data():
    """Inject language data into all templates"""
    return {
        '_': _,
        'language_info': language_manager.get_language_info(),
        'current_language': language_manager.get_current_language(),
        'translations': language_manager.get_all_translations(),
        'translate_device_type': language_manager.get_device_type_translation
    }

@app.route('/set-language/<language_code>')
def set_language(language_code):
    """Set the current language"""
    if language_manager.set_language(language_code):
        # Redirect back to the referring page or home
        return redirect(request.referrer or url_for('index'))
    else:
        return jsonify({'error': _('invalid_language')}), 400

@app.route('/api/language/info')
def get_language_info():
    """Get language information"""
    return jsonify(language_manager.get_language_info())

@app.route('/api/language/set', methods=['POST'])
def api_set_language():
    """API endpoint to set language"""
    data = request.get_json()
    language_code = data.get('language')
    
    if language_manager.set_language(language_code):
        return jsonify({
            'success': True,
            'message': _('language_changed'),
            'current_language': language_manager.get_current_language()
        })
    else:
        return jsonify({
            'success': False,
            'error': _('invalid_language')
        }), 400

@app.route('/api/language/translations/<language_code>')
def get_translations(language_code):
    """Get translations for a specific language"""
    return jsonify(language_manager.get_all_translations(language_code))

@app.route('/api/device-types/translated')
def get_translated_device_types():
    """Get device types translated to current language"""
    # Load device types from config
    config_manager = scanner.get_config_manager()
    device_types_config = config_manager.load_device_types()
    current_language = language_manager.get_current_language()
    
    translated_types = {}
    for device_type, info in device_types_config.items():
        translated_name = language_manager.get_device_type_translation(device_type, current_language)
        translated_types[device_type] = {
            'name': translated_name,
            'icon': info.get('icon', '❓'),
            'category': info.get('category', 'unknown')
        }
    
    return jsonify(translated_types)

def progress_callback(message):
    """Callback function for scan progress"""
    global scan_progress
    scan_progress["message"] = message
    # Accept both Turkish and English for backward compatibility
    if ("cihaz bulundu" in message) or ("device(s) found" in message):
        try:
            # Extract the number of devices from the message
            devices_count = int(message.split()[0])
            scan_progress["devices_found"] = devices_count
        except Exception:
            pass

def detailed_analysis_callback(message):
    """Callback function for detailed analysis progress"""
    global background_analysis
    background_analysis["message"] = message

def scan_network_thread():
    """Run network scan in a separate thread"""
    global scan_progress
    try:
        start_time = datetime.now()
        scan_progress["status"] = "scanning"
        scanner.scan_network(progress_callback)
        scanner.save_to_json()
        
        # Save scan results to history
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        devices = scanner.get_devices()
        online_devices = [d for d in devices if d.get('status') == 'online']
        
        # Calculate device type and vendor statistics
        device_types = {}
        vendors = {}
        for device in devices:
            device_type = device.get('device_type', 'Unknown')
            vendor = device.get('vendor', 'Unknown')
            device_types[device_type] = device_types.get(device_type, 0) + 1
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        # Save scan result to history
        config_manager = scanner.get_config_manager()
        scan_result = {
            "timestamp": end_time.isoformat(),
            "ip_range": getattr(config_manager, 'config', {}).get('scan_settings', {}).get('default_ip_range', 'Auto'),
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "scan_duration": scan_duration,
            "device_types": device_types,
            "vendors": vendors
        }
        config_manager.save_scan_result(scan_result)
        
        scan_progress["status"] = "completed"
        scan_progress["message"] = f"Scan completed! {len(devices)} device(s) found."
    except Exception as e:
        scan_progress["status"] = "error"
        scan_progress["message"] = f"Scan error: {str(e)}"

def scan_network_custom_thread(ip_range=None, include_offline=False):
    """Run network scan with custom settings in a separate thread"""
    global scan_progress
    try:
        start_time = datetime.now()
        scan_progress["status"] = "scanning"
        scanner.scan_network(progress_callback, ip_range, include_offline)
        scanner.save_to_json()
        
        # Save scan results to history
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        devices = scanner.get_devices()
        online_devices = [d for d in devices if d.get('status') == 'online']
        
        # Calculate device type and vendor statistics
        device_types = {}
        vendors = {}
        for device in devices:
            device_type = device.get('device_type', 'Unknown')
            vendor = device.get('vendor', 'Unknown')
            device_types[device_type] = device_types.get(device_type, 0) + 1
            vendors[vendor] = vendors.get(vendor, 0) + 1
        
        # Save scan result to history
        config_manager = scanner.get_config_manager()
        scan_result = {
            "timestamp": end_time.isoformat(),
            "ip_range": ip_range or 'Auto',
            "total_devices": len(devices),
            "online_devices": len(online_devices),
            "scan_duration": scan_duration,
            "device_types": device_types,
            "vendors": vendors,
            "include_offline": include_offline
        }
        config_manager.save_scan_result(scan_result)
        
        scan_progress["status"] = "completed"
        scan_progress["message"] = f"Scan completed! {len(devices)} device(s) found."
    except Exception as e:
        scan_progress["status"] = "error"
        scan_progress["message"] = f"Scan error: {str(e)}"

def run_detailed_analysis():
    """Run detailed analysis in a separate thread"""
    global background_analysis
    try:
        background_analysis["status"] = "analyzing"
        scanner.perform_detailed_analysis(detailed_analysis_callback)
        background_analysis["status"] = "completed"
        background_analysis["message"] = "Detailed analysis completed!"
    except Exception as e:
        background_analysis["status"] = "error"
        background_analysis["message"] = f"Detailed analysis error: {str(e)}"

def run_single_device_analysis(ip_address):
    """Run detailed device analysis in a separate thread"""
    global background_analysis
    try:
        background_analysis["status"] = "analyzing"
        scanner.perform_single_device_detailed_analysis(ip_address, detailed_analysis_callback)
        background_analysis["status"] = "completed"
        background_analysis["message"] = f"Detailed analysis completed: {ip_address}"
    except Exception as e:
        background_analysis["status"] = "error"
        background_analysis["message"] = f"Detailed analysis error: {str(e)}"

@app.route('/test_detailed_analysis')
def test_detailed_analysis():
    """Test page"""
    return send_from_directory('.', 'test_detailed_analysis.html')

@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files with proper cache control"""
    response = send_from_directory(os.path.join(app.root_path, 'static'), filename)
    
    # Prevent aggressive caching for development and dynamic content
    if filename.endswith('.js') or filename.endswith('.css'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    
    return response

@app.route('/favicon.ico')
def favicon():
    """Serve favicon.ico"""
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/')
def index():
    """Home page"""
    # Load previous scan results
    scanner.load_from_json()
    devices = scanner.get_devices()
    
    # Get device types from config
    config_manager = scanner.get_config_manager()
    device_types = config_manager.load_device_types()
    
    return render_template('index.html', devices=devices, device_types=device_types)

@app.route('/config')
def config_page():
    """Config/Settings page"""
    config_manager = scanner.get_config_manager()
    
    # Load current settings
    oui_database = config_manager.load_oui_database()
    device_types = config_manager.load_device_types()
    scan_settings = config_manager.get_setting('scan_settings', {})
    port_settings = config_manager.get_setting('port_settings', {})
    detection_rules = config_manager.get_setting('detection_rules', {})
    
    # Available networks
    available_networks = scanner.get_available_networks()
    
    return render_template('config.html', 
                         oui_database=oui_database,
                         device_types=device_types,
                         scan_settings=scan_settings,
                         port_settings=port_settings,
                         detection_rules=detection_rules,
                         available_networks=available_networks)

@app.route('/history')
def history_page():
    """History and statistics page"""
    config_manager = scanner.get_config_manager()
    scan_history = config_manager.load_scan_history()
    
    return render_template('history.html', scan_history=scan_history)

@app.route('/scan')
def start_scan():
    """Start a new scan"""
    global scan_thread, scan_progress
    
    if scan_progress["status"] == "scanning":
        return jsonify({"error": "Scan is already in progress"}), 400
    
    # Start the scan thread
    scan_thread = threading.Thread(target=scan_network_thread)
    scan_thread.daemon = True
    scan_thread.start()
    
    return jsonify({"message": "Scan started"})

@app.route('/scan_custom', methods=['POST'])
def start_custom_scan():
    """Start a scan with custom settings"""
    global scan_thread, scan_progress
    
    if scan_progress["status"] == "scanning":
        return jsonify({"error": "Scan is already in progress"}), 400
    
    try:
        data = request.json
        ip_range = data.get('ip_range')
        include_offline = data.get('include_offline', False)
        
        # Start the custom scan thread
        scan_thread = threading.Thread(
            target=lambda: scan_network_custom_thread(ip_range, include_offline)
        )
        scan_thread.daemon = True
        scan_thread.start()
        
        return jsonify({"message": "Custom scan started"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/stop_scan')
def stop_scan():
    """Stop the scan"""
    global scan_progress
    scanner.stop_scan()
    scan_progress["status"] = "stopped"
    scan_progress["message"] = "Scan stopped"
    return jsonify({"message": "Scan stopped"})

@app.route('/progress')
def get_progress():
    """Return scan progress"""
    return jsonify(scan_progress)

@app.route('/detailed_analysis')
def start_detailed_analysis():
    """Start bulk detailed analysis"""
    global detailed_analysis_thread, background_analysis
    
    if background_analysis["status"] == "analyzing":
        return jsonify({"error": "Detailed analysis is already running"}), 400
    
    # Clean up the previous thread
    if detailed_analysis_thread and detailed_analysis_thread.is_alive():
        return jsonify({"error": "Previous analysis is not yet completed"}), 400
    
    # Start a new thread
    thread = threading.Thread(target=run_detailed_analysis)
    thread.daemon = True
    thread.start()
    detailed_analysis_thread = thread
    
    return jsonify({"message": "Detailed analysis started"})

@app.route('/detailed_analysis_status')
def get_detailed_analysis_status():
    """Return detailed analysis status"""
    return jsonify(background_analysis)

@app.route('/analyze_device/<ip>')
def analyze_single_device(ip):
    """Start detailed analysis for a single device"""
    global detailed_analysis_thread, background_analysis
    
    if background_analysis["status"] == "analyzing":
        return jsonify({"error": "Detailed analysis is already running"}), 400
    
    # Clean up the previous thread
    if detailed_analysis_thread and detailed_analysis_thread.is_alive():
        return jsonify({"error": "Previous analysis is not yet completed"}), 400
    
    # Check if the device exists
    devices = scanner.get_devices()
    device = next((d for d in devices if d['ip'] == ip), None)
    if not device:
        return jsonify({"error": "Device not found"}), 404
    
    # Start a new thread
    thread = threading.Thread(target=run_single_device_analysis, args=(ip,))
    thread.daemon = True
    thread.start()
    detailed_analysis_thread = thread
    
    return jsonify({"message": f"Detailed analysis started: {ip}"})

@app.route('/devices')
@app.route('/get_devices')
def get_devices():
    """Return all devices as JSON"""
    devices = scanner.get_devices()
    return jsonify(devices)

@app.route('/device/<ip>')
def get_device(ip):
    """Return details of a specific device"""
    devices = scanner.get_devices()
    device = next((d for d in devices if d['ip'] == ip), None)
    if device:
        # Make JSON-safe - fix mixed key types
        safe_device = make_json_safe(device)
        return jsonify(safe_device)
    return jsonify({"error": "Device not found"}), 404

def make_json_safe(obj):
    """Make an object safe for JSON serialization"""
    import copy
    if isinstance(obj, dict):
        # Convert dict keys to strings and process values recursively
        safe_dict = {}
        for key, value in obj.items():
            safe_key = str(key)  # Convert all keys to strings
            safe_dict[safe_key] = make_json_safe(value)
        return safe_dict
    elif isinstance(obj, list):
        return [make_json_safe(item) for item in obj]
    elif isinstance(obj, (int, float, str, bool)) or obj is None:
        return obj
    else:
        # Convert other types to strings
        return str(obj)

@app.route('/update_device/<ip>', methods=['POST'])
def update_device(ip):
    """Update device information"""
    try:
        data = request.json
        success = scanner.update_device(ip, data)
        if success:
            scanner.save_to_json()
            return jsonify({"message": "Device updated"})
        return jsonify({"error": "Device not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analyze_device/<ip>')
def analyze_device(ip):
    """Perform detailed analysis for a specific device"""
    try:
        if scan_progress["status"] == "scanning":
            return jsonify({"error": "Cannot analyze while scan is in progress"}), 400
        
        analysis = scanner.detailed_device_analysis(ip)
        return jsonify(analysis)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analyze_device_background/<ip>')
def analyze_device_background(ip):
    """Start background detailed analysis for a specific device"""
    try:
        import uuid
        analysis_id = str(uuid.uuid4())
        
        # Start background analysis status
        background_analysis[analysis_id] = {
            "status": "starting",
            "ip": ip,
            "progress": 0,
            "message": "Starting analysis...",
            "start_time": datetime.now(),
            "result": None,
            "commands": [],
            "current_command": None
        }
        
        # Start background thread
        def background_analysis_thread():
            try:
                background_analysis[analysis_id]["status"] = "running"
                background_analysis[analysis_id]["message"] = "Performing detailed analysis..."
                
                # Execute commands sequentially - using Python-nmap for non-root
                commands = [
                    {"name": "Ping Test", "command": f"ping -c 4 {ip}"},
                    {"name": "Port Scan", "type": "nmap", "args": "-sT -p 1-1000"},
                    {"name": "Service Detection", "type": "nmap", "args": "-sT -sV"},
                    {"name": "OS Fingerprint", "type": "nmap", "args": "-sT -sV --version-all"},
                ]
                
                total_commands = len(commands)
                for i, cmd in enumerate(commands):
                    background_analysis[analysis_id]["current_command"] = cmd["name"]
                    background_analysis[analysis_id]["progress"] = int((i / total_commands) * 100)
                    background_analysis[analysis_id]["message"] = f"Running: {cmd['name']}"
                    
                    # Execute command - using Python-nmap or subprocess
                    import subprocess
                    import time
                    import nmap
                    start_time = time.time()
                    try:
                        if cmd.get("type") == "nmap":
                            # Use Python-nmap (does not require root)
                            nm = nmap.PortScanner()
                            result = nm.scan(ip, arguments=cmd["args"])
                            output = f"Nmap scan completed for {ip}\n"
                            if ip in result['scan']:
                                host_info = result['scan'][ip]
                                if 'tcp' in host_info:
                                    output += f"TCP ports: {list(host_info['tcp'].keys())}\n"
                                    for port, port_data in host_info['tcp'].items():
                                        output += f"Port {port}: {port_data.get('state', 'unknown')} - {port_data.get('name', 'unknown')}\n"
                            error = ""
                            return_code = 0
                        else:
                            # Use subprocess
                            result = subprocess.run(
                                cmd["command"].split(), 
                                capture_output=True, 
                                text=True, 
                                timeout=30
                            )
                            output = result.stdout
                            error = result.stderr
                            return_code = result.returncode
                        
                        end_time = time.time()
                        
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": output,
                            "error": error,
                            "duration": round(end_time - start_time, 2),
                            "return_code": return_code
                        })
                        
                    except subprocess.TimeoutExpired:
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": "Command timed out",
                            "error": "Timeout",
                            "duration": 30.0,
                            "return_code": -1
                        })
                    except Exception as e:
                        background_analysis[analysis_id]["commands"].append({
                            "name": cmd["name"],
                            "command": cmd.get("command", f"nmap {cmd.get('args', '')} {ip}"),
                            "output": "",
                            "error": str(e),
                            "duration": 0,
                            "return_code": -1
                        })
                
                # Analysis completed
                background_analysis[analysis_id]["status"] = "completed"
                background_analysis[analysis_id]["progress"] = 100
                background_analysis[analysis_id]["message"] = "Analysis completed"
                background_analysis[analysis_id]["end_time"] = datetime.now()
                
                # Create enhanced analysis result
                analysis_result = scanner.detailed_device_analysis(ip)
                background_analysis[analysis_id]["result"] = analysis_result
                
            except Exception as e:
                background_analysis[analysis_id]["status"] = "error"
                background_analysis[analysis_id]["message"] = f"Analysis error: {str(e)}"
                background_analysis[analysis_id]["error"] = str(e)
        
        # Start the thread
        analysis_thread = threading.Thread(target=background_analysis_thread)
        analysis_thread.daemon = True
        analysis_thread.start()
        
        return jsonify({
            "analysis_id": analysis_id,
            "message": "Background analysis started"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/analysis_status/<analysis_id>')
def get_analysis_status(analysis_id):
    """Get background analysis status"""
    if analysis_id in background_analysis:
        analysis = background_analysis[analysis_id].copy()
        
        # Convert datetime objects to strings
        if 'start_time' in analysis:
            analysis['start_time'] = analysis['start_time'].isoformat()
        if 'end_time' in analysis:
            analysis['end_time'] = analysis['end_time'].isoformat()
            
        return jsonify(analysis)
    else:
        return jsonify({"error": "Analysis not found"}), 404

@app.route('/export')
def export_data():
    """Export data as JSON"""
    devices = scanner.get_devices()
    return jsonify({
        "export_date": datetime.now().isoformat(),
        "total_devices": len(devices),
        "devices": devices
    })

@app.route('/import', methods=['POST'])
def import_data():
    """Import JSON data"""
    try:
        data = request.json
        if 'devices' in data:
            scanner.devices = data['devices']
            scanner.save_to_json()
            return jsonify({"message": f"{len(data['devices'])} devices imported"})
        return jsonify({"error": "Invalid data format"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Configuration API endpoints
@app.route('/api/config/oui', methods=['GET', 'POST'])
def manage_oui_database():
    """Manage OUI database"""
    if request.method == 'GET':
        return jsonify(oui_manager.export_database())
    
    elif request.method == 'POST':
        try:
            data = request.json
            oui_manager.import_database(data)
            return jsonify({"message": "OUI database updated"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/oui/update', methods=['POST'])
def update_oui_database():
    """Update OUI database from IEEE sources"""
    try:
        success = oui_manager.update_database()
        stats = oui_manager.get_stats()
        return jsonify({
            "success": success,
            "message": "OUI database updated" if success else "Update failed",
            "stats": stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/lookup/<mac>')
def lookup_oui(mac):
    """Get vendor information from MAC address"""
    try:
        vendor = oui_manager.get_vendor(mac)
        return jsonify({
            "mac": mac,
            "vendor": vendor
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/search')
def search_oui():
    """Search OUI by vendor name"""
    try:
        query = request.args.get('q', '')
        if not query:
            return jsonify({"error": "Query parameter required"}), 400
        
        results = oui_manager.search_vendor(query)
        return jsonify({
            "query": query,
            "results": results,
            "count": len(results)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/oui/stats')
def oui_stats():
    """OUI database statistics"""
    try:
        return jsonify(oui_manager.get_stats())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/config/device_types', methods=['GET', 'POST'])
def manage_device_types():
    """Manage device types"""
    config_manager = scanner.get_config_manager()
    
    if request.method == 'GET':
        return jsonify(config_manager.load_device_types())
    
    elif request.method == 'POST':
        try:
            data = request.json
            config_manager.save_device_types(data)
            scanner.load_config_settings()  # Reload settings
            return jsonify({"message": "Device types updated"})
        except Exception as e:
            return jsonify({"error": str(e)}), 400

@app.route('/api/config/settings', methods=['GET', 'POST'])
def manage_settings():
    """Manage general settings"""
    config_manager = scanner.get_config_manager()
    
    if request.method == 'GET':
        return jsonify({
            'scan_settings': config_manager.config.get('scan_settings', {}),
            'port_settings': config_manager.config.get('port_settings', {}),
            'detection_rules': config_manager.config.get('detection_rules', {})
        })
    
    elif request.method == 'POST':
        try:
            data = request.json
            
            # Update all sections first, then save
            for section, settings in data.items():
                if section not in config_manager.config:
                    config_manager.config[section] = {}
                
                for key, value in settings.items():
                    config_manager.config[section][key] = value
            
            # Save in one go
            config_manager.save_config()
            scanner.load_config_settings()  # Reload settings
            
            return jsonify({"success": True, "message": "Settings updated"})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/networks')
def get_available_networks():
    """Return available network interfaces"""
    try:
        networks = scanner.get_available_networks()
        return jsonify(networks)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/scan_history')
def get_scan_history():
    """Return scan history"""
    try:
        config_manager = scanner.get_config_manager()
        history = config_manager.load_scan_history()
        return jsonify(history)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/version')
def get_app_version():
    """Return application version information"""
    try:
        return jsonify(get_version_info())
    except Exception as e:
        return jsonify({"error": str(e), "version": get_version()}), 400

@app.route('/api/sanitize_data', methods=['POST'])
def sanitize_device_data():
    """Sanitize device data - remove sensitive information"""
    try:
        sanitizer = DataSanitizer()
        devices_file = 'data/lan_devices.json'
        backup_file = 'data/lan_devices_backup.json'
        
        # Create backup
        import shutil
        import os
        
        if os.path.exists(devices_file):
            shutil.copy2(devices_file, backup_file)
            
            # Sanitize the file
            if sanitizer.sanitize_file(devices_file):
                # Reload scanner data
                scanner.load_from_json()
                
                return jsonify({
                    "success": True,
                    "message": "Device data sanitized",
                    "backup_created": backup_file
                })
            else:
                return jsonify({
                    "success": False,
                    "error": "Data sanitization failed"
                }), 400
        else:
            return jsonify({
                "success": False,
                "error": "Device data file not found"
            }), 404
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/save_settings', methods=['POST'])
def save_settings():
    """Save settings - for config page"""
    try:
        data = request.json
        config_manager = scanner.get_config_manager()
        
        # Save settings
        for key, value in data.items():
            config_manager.config[key] = value
        
        config_manager.save_settings()
        scanner.load_config_settings()  # Reload settings
        
        return jsonify({"success": True, "message": "Settings saved"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/lookup_vendor/<mac>')
def lookup_vendor_api(mac):
    """Get vendor information from MAC address via API"""
    try:
        # Normalize MAC address
        clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac.upper())
        if len(clean_mac) < 6:
            return jsonify({"error": "Invalid MAC address"}), 400
        
        oui = clean_mac[:6]
        
        # Check local database first
        config_manager = scanner.get_config_manager()
        oui_db = config_manager.load_oui_database()
        
        if oui in oui_db:
            return jsonify({
                "success": True,
                "vendor": oui_db[oui],
                "source": "local_database"
            })
        
        # If not in local database, try APIs
        api_endpoints = [
            f"https://api.macvendorlookup.com/v2/{mac}",
            f"https://api.maclookup.app/v2/macs/{mac}",
            f"https://macvendors.co/api/{mac}"
        ]
        
        for endpoint in api_endpoints:
            try:
                response = requests.get(endpoint, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    
                    # Extract vendor name from API response
                    vendor = None
                    if isinstance(data, list) and len(data) > 0:
                        vendor = data[0].get('company') or data[0].get('vendor')
                    elif isinstance(data, dict):
                        vendor = data.get('company') or data.get('vendor') or data.get('result', {}).get('company')
                    
                    if vendor:
                        # Add to local database
                        oui_db[oui] = vendor
                        config_manager.save_oui_database(oui_db)
                        
                        return jsonify({
                            "success": True,
                            "vendor": vendor,
                            "source": "api_lookup",
                            "api": endpoint
                        })
                        
            except Exception as e:
                continue  # Try the next API
        
        return jsonify({
            "success": False,
            "error": "Vendor information not found"
        })
        
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/download_ieee_oui')
def download_ieee_oui():
    """Download and process IEEE OUI CSV file"""
    try:
        # Download IEEE OUI CSV file
        ieee_url = "https://standards-oui.ieee.org/oui/oui.csv"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/csv,application/csv,text/plain,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
        
        response = requests.get(ieee_url, headers=headers, timeout=60, verify=False)
        if response.status_code == 200:
            # Save the CSV file
            with open('config/oui_ieee.csv', 'w', encoding='utf-8') as f:
                f.write(response.text)
            
            # Process the CSV
            processed_count = process_ieee_csv('config/oui_ieee.csv')
            
            return jsonify({
                "success": True,
                "message": f"IEEE OUI database updated. {processed_count} records processed.",
                "processed_count": processed_count
            })
        else:
            return jsonify({
                "success": False,
                "error": f"Failed to download IEEE database. HTTP {response.status_code}"
            })
            
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        })

def process_ieee_csv(csv_file):
    """Process IEEE CSV file and add to OUI database"""
    try:
        config_manager = scanner.get_config_manager()
        oui_db = config_manager.load_oui_database()
        
        processed_count = 0
        
        with open(csv_file, 'r', encoding='utf-8') as f:
            csv_reader = csv.DictReader(f)
            for row in csv_reader:
                registry = row.get('Registry')
                assignment = row.get('Assignment')
                organization_name = row.get('Organization Name')
                
                if registry and assignment and organization_name:
                    # Normalize MAC prefix
                    mac_prefix = assignment.replace('-', '').upper()
                    if len(mac_prefix) == 6:  # 3-byte OUI
                        oui_db[mac_prefix] = organization_name.strip()
                        processed_count += 1
        
        # Save the updated database
        config_manager.save_oui_database(oui_db)
        return processed_count
        
    except Exception as e:
        print(f"CSV processing error: {e}")
        return 0
        

@app.route('/api/clear_history', methods=['POST'])
def clear_scan_history():
    """Clear scan history"""
    try:
        config_manager = scanner.get_config_manager()
        # Clear the history file
        with open(config_manager.scan_history_file, 'w', encoding='utf-8') as f:
            json.dump([], f)
        return jsonify({"success": True, "message": "History cleared"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/api/emojis', methods=['GET'])
def get_emojis():
    """Get emoji data from CSV file"""
    try:
        emojis_file = os.path.join('config', 'emojis.csv')
        emojis_data = []
        categories = set()
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    emojis_data.append({
                        'emoji': row['emoji'],
                        'category': row['category'],
                        'description': row['description'],
                        'keywords': row['keywords']
                    })
                    categories.add(row['category'])
        
        return jsonify({
            'emojis': emojis_data,
            'categories': sorted(list(categories)),
            'total_count': len(emojis_data)
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis/categories')
def get_emoji_categories():
    """Get emoji categories"""
    try:
        emojis_file = os.path.join('config', 'emojis.csv')
        categories = set()
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    categories.add(row['category'])
        
        return jsonify(sorted(list(categories)))
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis/search')
def search_emojis():
    """Search emojis"""
    try:
        query = request.args.get('q', '').lower()
        category = request.args.get('category', '')
        
        emojis_file = os.path.join('config', 'emojis.csv')
        results = []
        
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Category filter
                    if category and row['category'] != category:
                        continue
                    
                    # Search filter
                    if query:
                        searchable_text = f"{row['description']} {row['keywords']}".lower()
                        if query not in searchable_text:
                            continue
                    
                    results.append({
                        'emoji': row['emoji'],
                        'category': row['category'],
                        'description': row['description'],
                        'keywords': row['keywords']
                    })
        
        return jsonify({
            'results': results,
            'count': len(results),
            'query': query,
            'category': category
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route('/api/emojis', methods=['POST'])
def add_emoji():
    """Add a new emoji"""
    try:
        data = request.json
        emoji = data.get('emoji', '').strip()
        category = data.get('category', '').strip()
        description = data.get('description', '').strip()
        keywords = data.get('keywords', '').strip()
        
        if not all([emoji, category, description, keywords]):
            return jsonify({"error": "All fields are required"}), 400
        
        emojis_file = os.path.join('config', 'emojis.csv')
        
        # Check existing emojis
        existing_emojis = set()
        if os.path.exists(emojis_file):
            with open(emojis_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    existing_emojis.add(row['emoji'])
        
        if emoji in existing_emojis:
            return jsonify({"error": "This emoji already exists"}), 400
        
        # Add new emoji
        with open(emojis_file, 'a', encoding='utf-8', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([emoji, category, description, keywords])
        
        return jsonify({"message": "Emoji added successfully"})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# Docker API Endpoints
@app.route('/api/docker/networks')
def get_docker_networks():
    """Return Docker networks"""
    try:
        networks = docker_manager.get_docker_networks()
        return jsonify({
            "success": True,
            "networks": networks,
            "count": len(networks)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/containers')
def get_docker_containers():
    """Return Docker containers"""
    try:
        containers = docker_manager.get_docker_containers()
        return jsonify({
            "success": True,
            "containers": containers,
            "count": len(containers)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/scan_ranges')
def get_docker_scan_ranges():
    """Return scan ranges from Docker networks"""
    try:
        scan_ranges = docker_manager.get_docker_scan_ranges()
        return jsonify({
            "success": True,
            "scan_ranges": scan_ranges,
            "count": len(scan_ranges)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/interfaces')
def get_docker_interfaces():
    """Return Docker virtual interfaces"""
    try:
        interfaces = docker_manager.get_docker_interface_info()
        return jsonify({
            "success": True,
            "interfaces": interfaces,
            "count": len(interfaces)
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 400

@app.route('/api/docker/stats')
def get_docker_stats():
    """Return Docker general statistics"""
    try:
        stats = docker_manager.get_docker_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({
            "available": False,
            "error": str(e)
        }), 400

@app.route('/device_access/<ip>', methods=['GET', 'POST'])
def device_access(ip):
    """Manage device access information"""
    global credential_manager
    
    # Ensure credential manager is ready
    if not credential_manager:
        credential_manager = get_credential_manager()
    
    if request.method == 'GET':
        # Get existing access information (hide passwords)
        try:
            device_creds = credential_manager.get_device_credentials(ip) or {}
            # Hide passwords
            safe_creds = {}
            for access_type, creds in device_creds.items():
                safe_creds[access_type] = {
                    'username': creds.get('username'),
                    'port': creds.get('port'),
                    'additional_info': creds.get('additional_info', {}),
                    'created_at': creds.get('created_at'),
                    'has_password': bool(creds.get('password'))
                }
            return jsonify(safe_creds)
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    
    elif request.method == 'POST':
        # Save new access information
        try:
            access_data = request.json
            access_type = access_data.get('access_type')
            username = access_data.get('username')
            password = access_data.get('password')
            port = access_data.get('port')
            additional_info = access_data.get('additional_info', {})
            keep_existing_password = access_data.get('keep_existing_password', False)
            
            # If keeping existing password, retrieve the old password
            if keep_existing_password:
                existing_creds = credential_manager.get_device_credentials(ip, access_type)
                if existing_creds and existing_creds.get('password'):
                    password = existing_creds.get('password')
            
            # Save to secure credential manager
            success = credential_manager.save_device_credentials(
                ip, access_type, username, password, port, additional_info
            )
            
            if success:
                # Pass information to enhanced analyzer
                scanner.enhanced_analyzer.set_device_credentials(
                    ip, access_type, username, password, port, additional_info
                )
                
                return jsonify({"success": True, "message": "Access information securely saved"})
            else:
                return jsonify({"success": False, "error": "Credential save error"}), 400
                
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 400

@app.route('/test_device_access/<ip>', methods=['POST'])
def test_device_access(ip):
    """Test device access"""
    global credential_manager
    
    # Ensure credential manager is ready
    if not credential_manager:
        credential_manager = get_credential_manager()
    
    try:
        access_data = request.json
        access_type = access_data.get('access_type')
        use_stored_credentials = access_data.get('use_stored_credentials', False)
        
        if use_stored_credentials:
            # Retrieve credentials from secure storage
            stored_creds = credential_manager.get_device_credentials(ip, access_type)
            if stored_creds:
                username = stored_creds.get('username')
                password = stored_creds.get('password')
                port = stored_creds.get('port')
            else:
                return jsonify({"success": False, "error": "Stored credential not found"}), 400
        else:
            # Use credentials from POST
            username = access_data.get('username')
            password = access_data.get('password')
            port = access_data.get('port')
            
            if not password:
                # If password is empty and stored credentials exist, use them
                stored_creds = credential_manager.get_device_credentials(ip, access_type)
                if stored_creds and stored_creds.get('password'):
                    password = stored_creds.get('password')
        
        # Create credentials for testing
        test_credentials = {
            'username': username,
            'password': password,
            'port': int(port) if port else (22 if access_type == 'ssh' else 21 if access_type == 'ftp' else 23)
        }
        
        # Test results - test with temporary credentials
        test_result = credential_manager._test_credentials_direct(ip, access_type, test_credentials)
        
        return jsonify(test_result)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400

@app.route('/enhanced_analysis/<ip>', methods=['POST'])
def enhanced_analysis(ip):
    """Start enhanced device analysis"""
    global enhanced_analysis_status
    
    try:
        # Set status to analyzing
        enhanced_analysis_status[ip] = {
            "status": "analyzing", 
            "message": f"Starting enhanced analysis for {ip}...",
            "started_at": datetime.now().isoformat()
        }
        
        # Run enhanced analysis in background thread
        analysis_thread = threading.Thread(
            target=run_enhanced_analysis, 
            args=(ip,)
        )
        analysis_thread.start()
        
        return jsonify({
            "success": True, 
            "message": f"Enhanced analysis started for {ip}"
        })
        
    except Exception as e:
        enhanced_analysis_status[ip] = {
            "status": "error",
            "message": str(e)
        }
        return jsonify({"success": False, "error": str(e)}), 400

def merge_enhanced_info(existing, new_info):
    """Merge existing enhanced info with new information"""
    try:
        # Create deep copy
        import copy
        merged = copy.deepcopy(existing)
        
        for key, new_value in new_info.items():
            if key in merged:
                if isinstance(merged[key], dict) and isinstance(new_value, dict):
                    # If dict, merge recursively
                    merged[key] = merge_dict_recursive(merged[key], new_value)
                elif isinstance(merged[key], list) and isinstance(new_value, list):
                    # If list, merge and keep unique
                    merged[key] = merge_lists_unique(merged[key], new_value)
                else:
                    # For other types, take the new value
                    merged[key] = new_value
            else:
                # If new key, add directly
                merged[key] = new_value
        
        return merged
    except Exception as e:
        print(f"Enhanced info merge error: {e}")
        return new_info

def merge_dict_recursive(dict1, dict2):
    """Merge two dictionaries recursively"""
    import copy
    result = copy.deepcopy(dict1)
    
    for key, value in dict2.items():
        if key in result:
            if isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = merge_dict_recursive(result[key], value)
            elif isinstance(result[key], list) and isinstance(value, list):
                result[key] = merge_lists_unique(result[key], value)
            else:
                result[key] = value
        else:
            result[key] = value
    
    return result

def merge_lists_unique(list1, list2):
    """Merge two lists and keep unique"""
    try:
        # Use JSON serialization for unique check
        import json
        seen = set()
        merged = []
        
        for item in list1 + list2:
            # Serialize to JSON, use as hash
            try:
                item_hash = json.dumps(item, sort_keys=True) if isinstance(item, (dict, list)) else str(item)
                if item_hash not in seen:
                    seen.add(item_hash)
                    merged.append(item)
            except:
                # If not serializable, add directly
                merged.append(item)
        
        return merged
    except Exception as e:
        print(f"List merge error: {e}")
        return list1 + list2

def run_enhanced_analysis(ip):
    """Run enhanced analysis in background thread"""
    global enhanced_analysis_status
    
    try:
        # Update status
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"Retrieving information for {ip}..."
        }
        
        # Find the device
        device = None
        for d in scanner.get_devices():
            if d.get('ip') == ip:
                device = d
                break
        
        if not device:
            enhanced_analysis_status[ip] = {
                "status": "error",
                "message": f"Device {ip} not found"
            }
            print(f"Enhanced analysis: Device {ip} not found")
            return
        
        # Update status
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"Checking access information for {ip}..."
        }
        
        # Load credentials from secure storage and pass to enhanced analyzer
        credentials_set = False
        device_creds = credential_manager.get_device_credentials(ip)
        if device_creds:
            for access_type, creds in device_creds.items():
                scanner.enhanced_analyzer.set_device_credentials(
                    ip, access_type, 
                    creds.get('username'), 
                    creds.get('password'), 
                    creds.get('port'),
                    creds.get('additional_info')
                )
                print(f"Enhanced analysis: {access_type} credentials for {ip} loaded from secure storage")
                credentials_set = True
        
        if credentials_set:
            enhanced_analysis_status[ip]["message"] = f"Credentials set for {ip}, starting analysis..."
        else:
            enhanced_analysis_status[ip]["message"] = f"No credentials found for {ip}, performing general analysis..."
        
        # Progress tracking
        total_steps = 8  # Port scan, Web, SSH, FTP, SNMP, Hardware, IoT, Final
        current_step = 0
        
        # Progress callback
        def progress_callback(message):
            nonlocal current_step
            print(f"Enhanced analysis progress: {message}")
            
            # Update step number based on message
            if "Port Scan:" in message or "🔌" in message:
                current_step = max(current_step, 1)
            elif "Web Services" in message or "🌐" in message:
                current_step = max(current_step, 2)
            elif "SSH Analysis" in message or "🔐" in message:
                current_step = max(current_step, 3)
            elif "FTP Analysis" in message or "📁" in message:
                current_step = max(current_step, 4)
            elif "SNMP" in message or "📊" in message:
                current_step = max(current_step, 5)
            elif "Hardware" in message or "⚙️" in message:
                current_step = max(current_step, 6)
            elif "IoT" in message or "🏠" in message:
                current_step = max(current_step, 7)
            elif "saving results" in message:
                current_step = 8
            
            # Calculate progress percentage (5-95 range)
            progress_percent = max(5, min(95, 5 + (current_step / total_steps) * 90))
            
            enhanced_analysis_status[ip] = {
                "status": "analyzing",
                "message": message,
                "progress": progress_percent,
                "step": current_step,
                "total_steps": total_steps
            }
        
        print(f"Enhanced analysis: Starting comprehensive analysis for {ip}...")
        
        # Perform enhanced analysis
        enhanced_info = scanner.enhanced_analyzer.get_comprehensive_device_info(
            ip, 
            device.get('mac', ''),
            device.get('hostname', ''),
            device.get('vendor', ''),
            progress_callback=progress_callback
        )
        
        # Update status
        enhanced_analysis_status[ip] = {
            "status": "analyzing",
            "message": f"Saving analysis results for {ip}..."
        }
        
        print(f"Enhanced analysis: Analysis completed for {ip}, saving results...")
        
        # Preserve existing enhanced info and merge with new information
        existing_enhanced_info = device.get('enhanced_comprehensive_info', {})
        
        # Deep merge - preserve existing data while adding new data
        merged_enhanced_info = merge_enhanced_info(existing_enhanced_info, enhanced_info)
        
        # Merge enhanced analysis results with unified model
        enhanced_analysis_data = {
            "analysis_data": {
                "enhanced_analysis_info": merged_enhanced_info,
                "last_enhanced_analysis": datetime.now().isoformat()
            }
        }
        
        # Migrate existing device to unified format
        unified_device = unified_model.migrate_legacy_data(device)
        
        # Merge enhanced analysis results
        merged_device = unified_model.merge_device_data(unified_device, enhanced_analysis_data, "enhanced_analysis")
        
        # Write results back to device
        device.update(merged_device)
        
        # Update legacy fields for backward compatibility
        device['enhanced_comprehensive_info'] = merged_enhanced_info
        device['last_enhanced_analysis'] = datetime.now().isoformat()
        device['advanced_scan_summary'] = merged_enhanced_info
        device['enhanced_info'] = merged_enhanced_info
        
        # Add discovered services to open_ports using unified model
        discovered_ports = enhanced_info.get('discovered_ports', [])
        if discovered_ports:
            # Convert discovered ports to unified port format
            unified_ports = []
            for discovered_port in discovered_ports:
                unified_port = unified_model.create_unified_port(
                    discovered_port.get('port', 0),
                    service=discovered_port.get('service', 'unknown'),
                    state=discovered_port.get('state', 'open'),
                    version=discovered_port.get('version', ''),
                    product=discovered_port.get('product', ''),
                    description=discovered_port.get('description', ''),
                    manual=False,
                    source="enhanced_analysis"
                )
                unified_ports.append(unified_port)
            
            # Merge with existing ports
            current_ports = device.get('open_ports', [])
            merged_ports = unified_model.merge_ports(current_ports, unified_ports, "enhanced_analysis")
            device['open_ports'] = merged_ports
            
            print(f"Enhanced analysis: Ports merged for {ip} using unified model")
        
        # Save
        scanner.save_to_json()
        
        # Successfully completed
        enhanced_analysis_status[ip] = {
            "status": "completed",
            "message": f"Enhanced analysis successfully completed for {ip}",
            "completed_at": datetime.now().isoformat()
        }
        
        print(f"Enhanced analysis: Successfully completed for {ip}")
        
    except Exception as e:
        enhanced_analysis_status[ip] = {
            "status": "error",
            "message": f"Analysis error for {ip}: {str(e)}",
            "error_at": datetime.now().isoformat()
        }
        print(f"Enhanced analysis error for {ip}: {e}")
        import traceback
        traceback.print_exc()

@app.route('/enhanced_analysis_status/<ip>')
def enhanced_analysis_status_endpoint(ip):
    """Return enhanced analysis status"""
    global enhanced_analysis_status
    
    if ip in enhanced_analysis_status:
        return jsonify(enhanced_analysis_status[ip])
    else:
        # Fallback: check if device has enhanced info
        devices = scanner.get_devices()
        for device in devices:
            if device.get('ip') == ip:
                if 'enhanced_comprehensive_info' in device:
                    return jsonify({
                        "status": "completed",
                        "message": f"Enhanced analysis completed for {ip} (previously)"
                    })
                else:
                    return jsonify({
                        "status": "idle",
                        "message": f"No enhanced analysis performed for {ip}"
                    })
        
        return jsonify({
            "status": "error",
            "message": "Device not found"
        })

@app.route('/stop_enhanced_analysis/<ip>', methods=['POST'])
def stop_enhanced_analysis(ip):
    """Stop enhanced analysis"""
    global enhanced_analysis_status
    
    if ip in enhanced_analysis_status:
        enhanced_analysis_status[ip] = {
            "status": "stopped",
            "message": f"Analysis for {ip} stopped by user",
            "stopped_at": datetime.now().isoformat()
        }
        return jsonify({"success": True, "message": f"Analysis for {ip} stopped"})
    else:
        return jsonify({"success": False, "message": "No active analysis found"})

@app.route('/stop_bulk_analysis', methods=['POST'])
def stop_bulk_analysis():
    """Stop bulk analysis"""
    global bulk_analysis_status
    
    # Stop all active analyses
    bulk_analysis_status = {
        "status": "stopped",
        "message": "Bulk analysis stopped by user",
        "stopped_at": datetime.now().isoformat()
    }
    
    return jsonify({"success": True, "message": "Bulk analysis stopped"})

@app.route('/add_manual_device', methods=['POST'])
def add_manual_device():
    """Add a manual device"""
    try:
        data = request.json
        
        # Check required fields
        required_fields = ['ip', 'alias']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"success": False, "message": f"{field} is required"}), 400
        
        ip = data['ip'].strip()
        
        # Validate IP format
        import re
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        if not re.match(ip_pattern, ip):
            return jsonify({"success": False, "message": "Invalid IP address format"}), 400
        
        # Check existing devices
        devices = scanner.get_devices()
        existing_device = None
        for device in devices:
            if device.get('ip') == ip:
                existing_device = device
                break
        
        if existing_device:
            return jsonify({"success": False, "message": f"This IP address is already registered: {ip}"}), 400
        
        # Create new device
        new_device = {
            'ip': ip,
            'mac': data.get('mac', '').strip() or '',
            'hostname': data.get('hostname', '').strip() or '',
            'alias': data['alias'].strip(),
            'vendor': data.get('vendor', '').strip() or '',
            'device_type': data.get('device_type', '').strip() or 'Unknown',
            'notes': data.get('notes', '').strip() or '',
            'status': 'offline',  # Initially offline
            'last_seen': datetime.now().isoformat(),
            'open_ports': [],
            'manual_entry': True  # Mark as manually added device
        }
        
        # Add device to the list
        devices.append(new_device)
        
        # Save to file
        scanner.save_devices()
        
        print(f"Manual device added: {ip} ({new_device['alias']})")
        
        return jsonify({
            "success": True, 
            "message": f"Device successfully added: {new_device['alias']}",
            "device": new_device
        })
        
    except Exception as e:
        print(f"Error adding manual device: {e}")
        return jsonify({"success": False, "message": f"Error adding device: {str(e)}"}), 500

@app.route('/save_device', methods=['POST'])
def save_device():
    """Save/update a device"""
    try:
        data = request.json
        ip = data.get('ip')
        
        if not ip:
            return jsonify({"success": False, "message": "IP address is required"}), 400
        
        # Load the most recent data (including changes from credential manager)
        scanner.load_from_json()
        devices = scanner.get_devices()
        
        # Find the existing device
        device_found = False
        for i, device in enumerate(devices):
            if device.get('ip') == ip:
                # Update the device (preserve encrypted_credentials!)
                updates = {
                    'mac': data.get('mac', device.get('mac', '')),
                    'alias': data.get('alias', device.get('alias', '')),
                    'hostname': data.get('hostname', device.get('hostname', '')),
                    'vendor': data.get('vendor', device.get('vendor', '')),
                    'device_type': data.get('device_type', device.get('device_type', '')),
                    'notes': data.get('notes', device.get('notes', '')),
                    'last_modified': datetime.now().isoformat()
                }
                
                # Preserve encrypted credentials
                if 'encrypted_credentials' in device:
                    updates['encrypted_credentials'] = device['encrypted_credentials']
                
                device.update(updates)
                # Update scanner's internal list
                scanner.devices[i] = device
                device_found = True
                break
        
        if not device_found:
            # Add new device
            new_device = {
                'ip': ip,
                'mac': data.get('mac', ''),
                'alias': data.get('alias', ''),
                'hostname': data.get('hostname', ''),
                'vendor': data.get('vendor', ''),
                'device_type': data.get('device_type', ''),
                'notes': data.get('notes', ''),
                'status': 'offline',
                'last_seen': datetime.now().isoformat(),
                'last_modified': datetime.now().isoformat(),
                'open_ports': []
            }
            devices.append(new_device)
        
        # Save to file
        scanner.save_devices()
        
        return jsonify({
            "success": True,
            "message": "Device successfully saved"
        })
        
    except Exception as e:
        return jsonify({"success": False, "message": f"Error saving device: {str(e)}"}), 500

@app.route('/delete_device/<ip>', methods=['DELETE'])
def delete_device(ip):
    """Delete a device"""
    try:
        devices = scanner.get_devices()
        device_found = False
        device_name = ip
        
        # Find and delete the device
        for i, device in enumerate(devices):
            if device.get('ip') == ip:
                device_name = device.get('alias') or device.get('hostname') or ip
                devices.pop(i)
                device_found = True
                break
        
        if not device_found:
            return jsonify({"success": False, "message": "Device not found"}), 404
        
        # Save to file
        scanner.save_devices()
        
        print(f"Device deleted: {ip} ({device_name})")
        
        return jsonify({
            "success": True, 
            "message": f"Device successfully deleted: {device_name}"
        })
        
    except Exception as e:
        print(f"Error deleting device: {e}")
        return jsonify({"success": False, "message": f"Error deleting device: {str(e)}"}), 500


@app.route('/save_device_credentials', methods=['POST'])
def save_device_credentials():
    """Save device access information"""
    try:
        data = request.json
        ip = data.get('ip')
        access_type = data.get('access_type', 'ssh')
        
        if not ip:
            return jsonify({"error": "IP address is required"}), 400
        
        success = credential_manager.save_device_credentials(
            ip=ip,
            access_type=access_type,
            username=data.get('username', ''),
            password=data.get('password', ''),
            port=data.get('port', ''),
            additional_info={'notes': data.get('notes', '')}
        )
        
        if success:
            return jsonify({"success": True, "message": "Access information saved"})
        else:
            return jsonify({"error": "Save failed"}), 500
            
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get_device_types')
def get_device_types():
    """Return device types"""
    try:
        return jsonify(scanner.device_types)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_device_credentials/<ip>')
def get_device_credentials(ip):
    """Return device access information"""
    try:
        if not credential_manager:
            return jsonify({"error": "Credential manager not initialized"}), 500
        
        access_type = request.args.get('access_type', 'ssh')
        credentials = credential_manager.get_device_credentials(ip, access_type)
        if credentials:
            return jsonify(credentials)
        else:
            return jsonify({}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/get_active_analyses')
def get_active_analyses():
    """Return active analysis processes"""
    global enhanced_analysis_status, bulk_analysis_status
    
    active_analyses = {}
    
    # Single device analyses
    for ip, status in enhanced_analysis_status.items():
        if status.get('status') == 'analyzing':
            active_analyses[ip] = {
                'type': 'single',
                'status': status.get('status'),
                'message': status.get('message'),
                'progress': status.get('progress', 0),
                'step': status.get('step', 0),
                'total_steps': status.get('total_steps', 8),
                'analysis_results': status.get('analysis_results', {}),
                'completed_steps': status.get('completed_steps', [])
            }
    
    # Bulk analysis
    if bulk_analysis_status.get('status') == 'analyzing':
        active_analyses['bulk'] = {
            'type': 'bulk',
            'status': bulk_analysis_status.get('status'),
            'message': bulk_analysis_status.get('message'),
            'progress': bulk_analysis_status.get('progress', 0),
            'current_device': bulk_analysis_status.get('current_device', ''),
            'completed_devices': bulk_analysis_status.get('completed_devices', [])
        }
    
    return jsonify(active_analyses)

@app.route('/save_analysis_temp', methods=['POST'])
def save_analysis_temp():
    """Save analysis temp file"""
    try:
        data = request.json
        session_key = data.get('session_key')
        analysis_data = data.get('analysis_data', {})
        
        if not session_key:
            return jsonify({'error': 'Session key is required'}), 400
        
        # Temp file directory
        temp_dir = os.path.join('data', 'temp')
        os.makedirs(temp_dir, exist_ok=True)
        
        # File path
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        # Save
        with open(temp_file, 'w', encoding='utf-8') as f:
            json.dump(analysis_data, f, ensure_ascii=False, indent=2)
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/load_analysis_temp/<session_key>')
def load_analysis_temp(session_key):
    """Load analysis temp file"""
    try:
        temp_dir = os.path.join('data', 'temp')
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        if os.path.exists(temp_file):
            with open(temp_file, 'r', encoding='utf-8') as f:
                analysis_data = json.load(f)
            return jsonify(analysis_data)
        else:
            return jsonify({'error': 'Temp file not found'}), 404
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/clear_analysis_temp/<session_key>', methods=['POST'])
def clear_analysis_temp(session_key):
    """Clear analysis temp file"""
    try:
        temp_dir = os.path.join('data', 'temp')
        temp_file = os.path.join(temp_dir, f'analysis_{session_key.replace(".", "_")}.json')
        
        if os.path.exists(temp_file):
            os.remove(temp_file)
        
        return jsonify({'status': 'success'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/credentials/stats')
def get_credential_stats():
    """Return credential statistics"""
    global credential_manager
    try:
        stats = credential_manager.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == '__main__':
    # Load JSON file if exists
    scanner.load_from_json()
    
    print("LAN Scanner Web UI is starting...")
    print("Open http://localhost:5883 in your browser")
    print("Config page: http://localhost:5883/config")
    print("History page: http://localhost:5883/history")
    
    port = int(os.environ.get('FLASK_PORT', 5883))
    app.run(debug=True, host='0.0.0.0', port=port)
