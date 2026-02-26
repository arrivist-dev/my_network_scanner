#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAN Scanner - Scans devices on the network and collects detailed information
Enhanced version with configuration management and OUI integration
"""

# Warnings and logging settings
import warnings
import logging

# Suppress Scapy and network warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, module="scapy")

# Disable Scapy verbose output
import os
os.environ['SCAPY_VERBOSE'] = '0'

# Limit console logging
logging.getLogger("scapy").setLevel(logging.ERROR)

import nmap
# import netifaces  # Use network_utils instead for Docker compatibility
from network_utils import get_network_interfaces, get_default_gateway, get_local_ip_ranges, get_host_network_ranges, is_docker_environment
import json
import socket
import re
import subprocess
import os
from datetime import datetime
# Import Scapy silently
import sys
from io import StringIO

# Temporarily capture STDOUT
old_stdout = sys.stdout
old_stderr = sys.stderr
sys.stdout = StringIO()
sys.stderr = StringIO()

try:
    from scapy.all import ARP, Ether, srp
finally:
    # Restore STDOUT
    sys.stdout = old_stdout
    sys.stderr = old_stderr
from mac_vendor_lookup import MacLookup
from config import ConfigManager
from oui_manager import OUIManager
from docker_manager import docker_manager
from credential_manager import get_credential_manager
from advanced_device_scanner import AdvancedDeviceScanner
from smart_device_identifier import SmartDeviceIdentifier
from hostname_resolver import AdvancedHostnameResolver
from enhanced_device_analyzer import EnhancedDeviceAnalyzer
from data_sanitizer import DataSanitizer
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import base64
from unified_device_model import unified_model

class LANScanner:
    def __init__(self):
        self.devices = []
        self.mac_lookup = MacLookup()
        self.oui_manager = OUIManager()
        self.scanning = False
        self.config_manager = ConfigManager()
        self.credential_manager = get_credential_manager()
        self.data_sanitizer = DataSanitizer()
        
        # New advanced modules
        self.advanced_scanner = AdvancedDeviceScanner()
        self.enhanced_analyzer = EnhancedDeviceAnalyzer(self.credential_manager)
        self.smart_identifier = SmartDeviceIdentifier(self.config_manager)
        self.hostname_resolver = AdvancedHostnameResolver()
        
        # Load settings from config
        self.load_config_settings()
        
    def load_config_settings(self):
        """Load settings from the config file"""
        self.oui_database = self.config_manager.load_oui_database()
        self.device_types = self.config_manager.load_device_types()
        
        # Get settings correctly from config
        config = getattr(self.config_manager, 'config', {})
        self.detection_rules = config.get('detection_rules', {})
        self.scan_settings = config.get('scan_settings', {})
        self.port_settings = config.get('port_settings', {})
        self.smart_naming_config = config.get('smart_naming', {
            'enabled': False,
            'auto_alias': True,
            'hostname_resolution': True,
            'advanced_scanning': True,
            'confidence_threshold': 0.5
        })
        
    def get_available_networks(self):
        """Returns all available network interfaces and IP ranges (including Docker networks)"""
        networks = []
        try:
            # Use network_utils to get interfaces
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                interface = interface_info['name']
                ip = interface_info['ip']
                netmask = interface_info['netmask']
                
                # Skip virtual and unused interfaces
                if (interface.startswith('anpi') or interface.startswith('utun') or 
                    interface.startswith('ipsec') or interface.startswith('llw') or
                    interface.startswith('awdl')):
                    continue
                
                # Skip loopback and link-local addresses
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                
                network_range = self._get_network_range(ip, netmask)
                networks.append({
                    'interface': interface,
                    'ip': ip,
                    'netmask': netmask,
                    'network_range': network_range,
                    'type': self._get_interface_type(interface)
                })
            
            # Add Docker networks
            docker_networks = self.get_docker_networks()
            networks.extend(docker_networks)
            
        except Exception as e:
            print(f"Network interface scan error: {e}")
            
        return networks

    def get_docker_networks(self):
        """Returns Docker network interfaces"""
        docker_networks = []
        
        try:
            # Get Docker virtual interfaces
            docker_interfaces = docker_manager.get_docker_interface_info()
            for interface in docker_interfaces:
                docker_networks.append({
                    'interface': interface['interface'],
                    'ip': interface['ip'],
                    'netmask': interface['netmask'],
                    'network_range': self._get_network_range(interface['ip'], interface['netmask']),
                    'type': 'Docker',
                    'description': interface['description']
                })
            
            # Get Docker container networks
            docker_ranges = docker_manager.get_docker_scan_ranges()
            for range_info in docker_ranges:
                # Parse network range
                subnet = range_info['subnet']
                if '/' in subnet:
                    try:
                        import ipaddress
                        network = ipaddress.ip_network(subnet, strict=False)
                        
                        docker_networks.append({
                            'interface': f"docker-{range_info['network_name']}",
                            'ip': str(network.network_address),
                            'netmask': str(network.netmask),
                            'network_range': subnet,
                            'type': 'Docker Network',
                            'description': f"Docker {range_info['driver']} network ({range_info['container_count']} containers)",
                            'docker_info': {
                                'network_name': range_info['network_name'],
                                'network_id': range_info['network_id'],
                                'driver': range_info['driver'],
                                'gateway': range_info['gateway'],
                                'container_count': range_info['container_count']
                            }
                        })
                    except Exception as e:
                        print(f"Docker network parse error: {e}")
                        continue
        
        except Exception as e:
            print(f"Failed to retrieve Docker network information: {e}")
        
        return docker_networks

    def scan_docker_containers_directly(self):
        """Directly detects Docker containers and adds them to the device list"""
        docker_devices = []
        
        try:
            # Get running containers
            containers = docker_manager.get_docker_containers()
            
            for container in containers:
                ip_addresses = container.get('ip_addresses', [])
                
                for ip_info in ip_addresses:
                    ip = ip_info.get('ipv4', '')
                    network = ip_info.get('network', '')
                    mac = ip_info.get('mac', '')
                    
                    if ip and ip != '':
                        # Create device info for the container
                        container_name = container['name']
                        # Clean container name (remove / character)
                        if container_name.startswith('/'):
                            container_name = container_name[1:]
                        
                        # Set hostname for Docker container as container name
                        hostname = container_name
                        
                        device = {
                            'ip': ip,
                            'mac': mac or 'Unknown',
                            'hostname': hostname,
                            'vendor': 'Docker',
                            'device_type': 'Docker Container',
                            'status': 'online',
                            'last_seen': datetime.now().isoformat(),
                            'response_time': 0,  # 0 ms for Docker containers
                            'open_ports': self._get_container_ports(container),
                            'docker_info': {
                                'container_id': container['id'],
                                'container_name': container_name,
                                'image': container['image'],
                                'network': network,
                                'status': container['status']
                            }
                        }
                        
                        docker_devices.append(device)
            
        except Exception as e:
            print(f"Docker container scan error: {e}")
        
        return docker_devices
    
    def _get_container_ports(self, container):
        """Parse open ports of the container"""
        ports = []
        ports_str = container.get('ports', '')
        
        if ports_str:
            # Parse port string: "0.0.0.0:55001->8978/tcp, [::]:55001->8978/tcp"
            import re
            
            # Find port mappings
            port_mappings = re.findall(r'(\d+)->', ports_str)
            for port in port_mappings:
                try:
                    ports.append(int(port))
                except ValueError:
                    continue
                    
            # Also find internal ports
            internal_ports = re.findall(r'->(\d+)/', ports_str)
            for port in internal_ports:
                try:
                    port_num = int(port)
                    if port_num not in ports:
                        ports.append(port_num)
                except ValueError:
                    continue
        
        return ports

    def _get_interface_type(self, interface):
        """Determine the type of network interface"""
        interface_lower = interface.lower()
        if 'docker' in interface_lower or interface_lower.startswith('br-') or 'veth' in interface_lower:
            return 'Docker'
        elif 'wlan' in interface_lower or 'wifi' in interface_lower or 'wi' in interface_lower:
            return 'WiFi'
        elif 'eth' in interface_lower or interface_lower.startswith('en'):
            # On MacOS, en0 is usually WiFi, others like en8 may be Ethernet
            if interface_lower == 'en0':
                return 'WiFi'
            else:
                return 'Ethernet'
        elif 'vpn' in interface_lower or 'tun' in interface_lower or 'tap' in interface_lower:
            return 'VPN'
        elif 'bluetooth' in interface_lower or 'bt' in interface_lower:
            return 'Bluetooth'
        elif 'bridge' in interface_lower or 'br' in interface_lower:
            return 'Bridge'
        else:
            return 'Other'

    def get_local_network(self, preferred_interface=None):
        """Automatically determines the local network range"""
        try:
            # Check default IP range from config
            default_range = self.scan_settings.get('default_ip_range', '192.168.1.0/24')
            
            # Use host networks in Docker environment
            if is_docker_environment():
                print("🐳 Docker container detected - scanning host networks")
                host_ranges = get_host_network_ranges()
                
                # Select the most suitable host network
                for range_info in host_ranges:
                    if range_info.get('is_host_network') and not range_info.get('is_common_range'):
                        # Prefer gateway-based host network
                        print(f"🌐 Host network selected: {range_info['cidr']}")
                        return range_info['cidr']
                
                # If gateway-based cannot be found, select one of the common ranges
                for range_info in host_ranges:
                    if range_info.get('is_host_network') and range_info.get('is_common_range'):
                        print(f"🌐 Common host network selected: {range_info['cidr']}")
                        return range_info['cidr']
            
            if preferred_interface:
                # If a specific interface is preferred
                networks = self.get_available_networks()
                for network in networks:
                    if network.get('interface') == preferred_interface:
                        return network.get('network_range', default_range)
            
            # Find the default gateway
            default_gateway = get_default_gateway()
            if default_gateway:
                # Check active network interfaces
                interfaces = get_network_interfaces()
                for interface_info in interfaces:
                    ip = interface_info['ip']
                    netmask = interface_info['netmask']
                    
                    # Check if the gateway is in this IP range
                    if self._is_ip_in_range(default_gateway, ip, netmask):
                        return self._get_network_range(ip, netmask)
            
            return default_range
        except Exception as e:
            print(f"Network detection error: {e}")
            return self.scan_settings.get('default_ip_range', '192.168.1.0/24')
    
    def _is_ip_in_range(self, ip, network_ip, netmask):
        """Checks if the IP is within the specified network range"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{network_ip}/{netmask}", strict=False)
            return ipaddress.IPv4Address(ip) in network
        except Exception:
            return False
    
    def _get_network_range(self, ip, netmask):
        """Calculates the network range from IP and netmask"""
        try:
            import ipaddress
            network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
            return str(network)
        except Exception:
            return "192.168.1.0/24"
    
    def get_local_machine_interfaces(self):
        """Detects all network interfaces of the local machine"""
        local_interfaces = []
        try:
            # Use network_utils to get interfaces
            interfaces = get_network_interfaces()
            for interface_info in interfaces:
                interface = interface_info['name']
                ip = interface_info['ip']
                
                # Skip virtual and unused interfaces
                if (interface.startswith('anpi') or interface.startswith('utun') or 
                    interface.startswith('ipsec') or interface.startswith('llw') or
                    interface.startswith('awdl') or interface.startswith('lo')):
                    continue
                
                # Skip loopback and link-local addresses
                if ip.startswith('127.') or ip.startswith('169.254.'):
                    continue
                
                # Get MAC address (using psutil)
                mac_addr = 'Unknown'
                try:
                    import psutil
                    net_if_addrs = psutil.net_if_addrs()
                    if interface in net_if_addrs:
                        for addr in net_if_addrs[interface]:
                            if addr.family == psutil.AF_LINK:
                                mac_addr = addr.address
                                break
                except:
                    pass
                
                local_interfaces.append({
                    'interface': interface,
                    'ip': ip,
                    'mac': mac_addr,
                    'type': self._get_interface_type(interface)
                })
        except Exception as e:
            print(f"Local interface scan error: {e}")
        
        return local_interfaces
    
    def get_local_machine_hostname(self):
        """Gets the hostname of the local machine"""
        try:
            import socket
            return socket.gethostname()
        except Exception:
            return "LocalMachine"
    
    def scan_network_arp(self, target_ip):
        """Performs a quick scan using ARP"""
        try:
            # Create ARP request
            arp = ARP(pdst=target_ip)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp
            
            # Send packets and receive responses
            result = srp(packet, timeout=3, verbose=0)[0]
            
            devices = []
            for sent, received in result:
                devices.append({
                    'ip': received.psrc,
                    'mac': received.hwsrc
                })
            
            return devices
        except Exception as e:
            print(f"ARP scan error: {e}")
            return []

    def get_hostname(self, ip):
        """Gets the hostname from the IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except Exception:
            return ""

    def get_device_vendor_enhanced(self, mac_address):
        """Enhanced manufacturer detection using OUI Manager"""
        return self.oui_manager.get_vendor(mac_address)
    
    def detect_device_type_smart_enhanced(self, ip, mac, hostname, vendor, open_ports):
        """Smart device type detection - Config-based"""
        hostname_lower = hostname.lower() if hostname else ""
        vendor_lower = vendor.lower() if vendor else ""
        
        # Check hostname patterns from config
        hostname_patterns = self.detection_rules.get('hostname_patterns', [])
        for rule in hostname_patterns:
            try:
                if re.search(rule['pattern'], hostname_lower, re.IGNORECASE):
                    return rule['type']
            except Exception:
                continue
        
        # Check vendor patterns from config
        vendor_patterns = self.detection_rules.get('vendor_patterns', [])
        for rule in vendor_patterns:
            try:
                if re.search(rule['pattern'], vendor_lower, re.IGNORECASE):
                    # Check additional conditions
                    if 'conditions' in rule:
                        conditions_met = any(
                            condition in hostname_lower or condition in vendor_lower 
                            for condition in rule['conditions']
                        )
                        if conditions_met:
                            return rule['type']
                    else:
                        return rule['type']
            except Exception:
                continue
        
        # Port-based prediction
        if open_ports:
            if any(port in [80, 443, 8080, 8443] for port in open_ports):
                if any(port in [22, 23] for port in open_ports):
                    return 'Router'
                elif 554 in open_ports or 8554 in open_ports:
                    return 'IP Camera'
                elif 631 in open_ports:
                    return 'Printer'
            
            if 22 in open_ports and hostname_lower:
                if 'pi' in hostname_lower or 'raspberry' in hostname_lower:
                    return 'Raspberry Pi'
                else:
                    return 'Server'
            
            if 3389 in open_ports:
                return 'Desktop'
        
        return 'Unknown'
    
    def scan_ports_basic(self, ip):
        """Quick basic port scan - only common ports"""
        try:
            # For quick scan, only the most common ports
            basic_ports = [22, 23, 80, 443, 8080]
            
            nm = nmap.PortScanner()
            port_range = ','.join(map(str, basic_ports))
            result = nm.scan(ip, port_range, arguments='-sT -T4 --max-retries 1 --host-timeout 10s')
            
            open_ports = []
            if ip in result['scan']:
                if 'tcp' in result['scan'][ip]:
                    for port, info in result['scan'][ip]['tcp'].items():
                        if info['state'] == 'open':
                            service = info.get('name', 'unknown')
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'state': info['state']
                            })
            
            return open_ports
        except Exception as e:
            print(f"Quick port scan error {ip}: {e}")
            return []

    def scan_ports_enhanced(self, ip, device_type=None):
        """Enhanced port scan - device type specific"""
        try:
            # Get default ports
            default_ports = self.port_settings.get('default_ports', [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 8080, 8443])
            
            # Add device type specific ports
            device_specific_ports = self.port_settings.get('device_specific_ports', {})
            if device_type and device_type in device_specific_ports:
                scan_ports = list(set(default_ports + device_specific_ports[device_type]))
            else:
                scan_ports = default_ports
            
            # Create port range string
            port_range = ','.join(map(str, scan_ports))
            
            nm = nmap.PortScanner()
            result = nm.scan(ip, port_range, arguments='-sT -T4 --max-retries 1 --host-timeout 30s')
            
            open_ports = []
            if ip in result['scan']:
                if 'tcp' in result['scan'][ip]:
                    for port, info in result['scan'][ip]['tcp'].items():
                        if info['state'] == 'open':
                            service = info.get('name', 'unknown')
                            version = info.get('version', '')
                            open_ports.append({
                                'port': port,
                                'service': service,
                                'version': version,
                                'state': info['state']
                            })
            
            return open_ports
        except Exception as e:
            print(f"Port scan error {ip}: {e}")
            return []

    def detailed_device_analysis(self, ip):
        """Detailed device analysis - ping, traceroute, service detection, etc."""
        analysis_results = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'ping_test': self._ping_test(ip),
            'traceroute': self._traceroute_test(ip),
            'service_detection': self._service_detection(ip),
            'os_detection': self._os_detection(ip)
        }
        
        return analysis_results
    
    def _ping_test(self, ip):
        """Ping test"""
        try:
            result = subprocess.run(['ping', '-c', '4', ip], 
                                  capture_output=True, text=True, timeout=10)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'response_time': self._extract_ping_time(result.stdout)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _traceroute_test(self, ip):
        """Traceroute test"""
        try:
            result = subprocess.run(['traceroute', '-m', '10', ip], 
                                  capture_output=True, text=True, timeout=30)
            return {
                'success': result.returncode == 0,
                'output': result.stdout,
                'hops': self._extract_hops(result.stdout)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _service_detection(self, ip):
        """Service detection"""
        try:
            nm = nmap.PortScanner()
            result = nm.scan(ip, arguments='-sT -sV --script=default')
            
            services = []
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                for port, info in result['scan'][ip]['tcp'].items():
                    if info['state'] == 'open':
                        services.append({
                            'port': port,
                            'service': info.get('name', 'unknown'),
                            'product': info.get('product', ''),
                            'version': info.get('version', ''),
                            'extrainfo': info.get('extrainfo', '')
                        })
            
            return services
        except Exception as e:
            return {'error': str(e)}
    
    def _os_detection(self, ip):
        """Operating system detection"""
        try:
            nm = nmap.PortScanner()
            # For OS detection, infer from service banners (does not require root)
            result = nm.scan(ip, arguments='-sT -sV --version-all')
            
            os_info = {}
            # Try to infer OS information from service versions
            if ip in result['scan'] and 'tcp' in result['scan'][ip]:
                services = []
                for port, info in result['scan'][ip]['tcp'].items():
                    if info['state'] == 'open':
                        service_info = info.get('product', '') + ' ' + info.get('version', '')
                        services.append(service_info.lower())
                
                # Try to infer OS from service information
                os_hints = []
                for service in services:
                    if 'linux' in service or 'ubuntu' in service or 'debian' in service:
                        os_hints.append('Linux')
                    elif 'windows' in service or 'microsoft' in service:
                        os_hints.append('Windows')
                    elif 'cisco' in service:
                        os_hints.append('Cisco IOS')
                    elif 'openssh' in service:
                        os_hints.append('Unix-like')
                
                if os_hints:
                    os_info = {
                        'name': max(set(os_hints), key=os_hints.count),
                        'accuracy': 60,  # Lower accuracy since it's based on service detection
                        'method': 'service_fingerprinting'
                    }
            
            return os_info
        except Exception as e:
            return {'error': str(e)}
    
    def _extract_ping_time(self, ping_output):
        """Extract response time from ping output"""
        try:
            pattern = r'time=(\d+\.?\d*)ms'
            matches = re.findall(pattern, ping_output)
            if matches:
                times = [float(match) for match in matches]
                return {
                    'min': min(times),
                    'max': max(times),
                    'avg': sum(times) / len(times)
                }
        except Exception:
            pass
        return None
    
    def _extract_hops(self, traceroute_output):
        """Extract hops from traceroute output"""
        try:
            lines = traceroute_output.strip().split('\n')
            hops = []
            for line in lines[1:]:  # First line is header
                if line.strip():
                    hops.append(line.strip())
            return hops
        except Exception:
            pass
        return []

    # Backward compatibility methods
    def get_device_vendor(self, mac_address):
        """Gets manufacturer information from MAC address - Backward compatibility"""
        return self.get_device_vendor_enhanced(mac_address)
    
    def detect_device_type_smart(self, ip, mac, hostname, vendor, open_ports):
        """Smart device type detection - Backward compatibility"""
        return self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, open_ports)
    
    def scan_ports(self, ip, port_range=None, device_type=None):
        """Port scan - Use enhanced version"""
        if port_range:
            # If called with old format
            try:
                nm = nmap.PortScanner()
                result = nm.scan(ip, port_range, arguments='-sT -T4 --max-retries 1 --host-timeout 30s')
                
                open_ports = []
                if ip in result['scan']:
                    if 'tcp' in result['scan'][ip]:
                        for port, info in result['scan'][ip]['tcp'].items():
                            if info['state'] == 'open':
                                service = info.get('name', 'unknown')
                                open_ports.append({
                                    'port': port,
                                    'service': service,
                                    'state': info['state']
                                })
                
                return open_ports
            except Exception as e:
                print(f"Port scan error {ip}: {e}")
                return []
        else:
            # Use new enhanced version
            return self.scan_ports_enhanced(ip, device_type)

    def scan_single_device(self, ip, mac, existing_devices=None, detailed_analysis=False, progress_callback=None, local_interface_info=None):
        """Scans a single device - if detailed_analysis=True, performs advanced analysis"""
        print(f"Scanning: {ip}")
        
        # Helper function for detailed logging
        def log_operation(operation, status="starting", details=""):
            if progress_callback and detailed_analysis:
                message = f"{ip} - {operation}: {status}"
                if details:
                    message += f" ({details})"
                progress_callback(message)
        
        # Check existing device info
        mac_lower = mac.lower()
        existing_device = existing_devices.get(mac_lower, {}) if existing_devices else {}
        
        # Get basic info - use existing info first
        existing_hostname = existing_device.get('hostname', '')
        existing_vendor = existing_device.get('vendor', '')
        
        log_operation("🔍 Hostname Resolution", "starting")
        
        # Special hostname for local machine
        if local_interface_info:
            hostname = self.get_local_machine_hostname()
            # Enrich local machine hostname with interface type
            if local_interface_info.get('interface_type'):
                hostname = f"{hostname} ({local_interface_info['interface_type']})"
            log_operation("🔍 Hostname Resolution", "local machine", hostname)
        elif existing_hostname and not detailed_analysis:
            # In quick scan, keep existing hostname
            hostname = existing_hostname
            log_operation("🔍 Hostname Resolution", "kept", hostname)
        else:
            hostname = self.get_hostname(ip)
            # If no new hostname, keep old
            if not hostname and existing_hostname:
                hostname = existing_hostname
                log_operation("🔍 Hostname Resolution", "old kept", hostname)
            else:
                log_operation("🔍 Hostname Resolution", "completed", hostname or "hostname not found")
        
        log_operation("🏷️ MAC Vendor Lookup", "starting")
        
        # Special vendor for local machine
        if local_interface_info:
            vendor = self.get_device_vendor_enhanced(mac)
            if not vendor or vendor == "Unknown":
                vendor = "Apple Inc." if mac.startswith(('00:e0:4c', '1e:48:ac')) else "Local Machine"
            log_operation("🏷️ MAC Vendor Lookup", "local machine", vendor)
        elif existing_vendor and not detailed_analysis:
            # In quick scan, keep existing vendor
            vendor = existing_vendor
            log_operation("🏷️ MAC Vendor Lookup", "kept", vendor)
        else:
            vendor = self.get_device_vendor_enhanced(mac)
            # If no new vendor, keep old
            if not vendor and existing_vendor:
                vendor = existing_vendor
                log_operation("🏷️ MAC Vendor Lookup", "old kept", vendor)
            else:
                log_operation("🏷️ MAC Vendor Lookup", "completed", vendor or "vendor not found")
        
        # Check if smart naming is enabled and detailed analysis requested
        smart_naming_enabled = self.smart_naming_config.get('enabled', False) and detailed_analysis
        
        # Advanced hostname resolution (only in detailed analysis)
        enhanced_hostname_info = None
        if smart_naming_enabled and self.smart_naming_config.get('hostname_resolution', True):
            try:
                log_operation("🧠 Advanced Hostname Analysis", "starting", "RDN & DNS analysis")
                enhanced_hostname_info = self.hostname_resolver.resolve_hostname_comprehensive(ip)
                if enhanced_hostname_info.get('primary_hostname'):
                    hostname = enhanced_hostname_info['primary_hostname']
                    log_operation("🧠 Advanced Hostname Analysis", "completed", f"hostname: {hostname}")
                else:
                    log_operation("🧠 Advanced Hostname Analysis", "completed", "no additional hostname found")
            except Exception as e:
                log_operation("🧠 Advanced Hostname Analysis", "error", str(e))
                print(f"Advanced hostname resolution error {ip}: {e}")
        
        # Port scan - more comprehensive in detailed analysis
        if detailed_analysis:
            log_operation("🔌 Advanced Port Scan", "starting", "all services")
            open_ports = self.scan_ports_enhanced(ip)
            log_operation("🔌 Advanced Port Scan", "completed", f"{len(open_ports)} ports found")
        else:
            # For quick scan, only basic ports
            log_operation("🔌 Quick Port Scan", "starting", "basic ports")
            open_ports = self.scan_ports_basic(ip)
            log_operation("🔌 Quick Port Scan", "completed", f"{len(open_ports)} ports found")
        
        port_numbers = [port['port'] if isinstance(port, dict) else port for port in open_ports]
        
        # Collect advanced device info (only in detailed analysis)
        enhanced_info = None
        if smart_naming_enabled and self.smart_naming_config.get('advanced_scanning', True):
            try:
                log_operation("🔬 Advanced Device Analysis", "starting", "DNS, SNMP, Web, SMB, UPnP")
                enhanced_info = self.advanced_scanner.get_enhanced_device_info(ip, mac, hostname, vendor, progress_callback)
                methods_count = len(enhanced_info.keys()) if enhanced_info else 0
                log_operation("🔬 Advanced Device Analysis", "completed", f"{methods_count} methods used")
            except Exception as e:
                log_operation("🔬 Advanced Device Analysis", "error", str(e))
                print(f"Advanced device analysis error {ip}: {e}")
        
        # Determine device type - ALWAYS keep user-set device_type
        if existing_device.get('device_type'):
            # Keep existing device_type (user entered)
            device_type = existing_device.get('device_type')
            identification_result = {'device_type': device_type, 'confidence': 1.0, 'user_defined': True}
            print(f"User-defined device_type kept: {device_type} ({ip})")
        elif local_interface_info:
            # Special device_type for local machine
            interface_type = local_interface_info.get('interface_type', 'Other')
            if interface_type == 'Ethernet':
                device_type = 'Desktop/Laptop (Ethernet)'
            elif interface_type == 'WiFi':
                device_type = 'Desktop/Laptop (WiFi)'
            else:
                device_type = f'Local Machine ({interface_type})'
            identification_result = {'device_type': device_type, 'confidence': 1.0, 'local_machine': True}
            print(f"Local machine device_type: {device_type} ({ip})")
        else:
            # Use smart identification (only for new devices or undefined ones)
            if smart_naming_enabled:
                try:
                    log_operation("🤖 Smart Device Identification", "starting", "AI algorithm")
                    device_info_for_id = {
                        'ip': ip,
                        'mac': mac,
                        'hostname': hostname,
                        'vendor': vendor,
                        'open_ports': open_ports
                    }
                    identification_result = self.smart_identifier.identify_device_with_enhanced_analysis(
                        device_info_for_id, enhanced_info
                    )
                    device_type = identification_result.get('device_type', 'unknown')
                    confidence = identification_result.get('confidence', 0)
                    log_operation("🤖 Smart Device Identification", "completed", f"{device_type} (confidence: {confidence:.2f})")
                    
                    # Check confidence threshold
                    confidence_threshold = self.smart_naming_config.get('confidence_threshold', 0.5)
                    if identification_result.get('confidence', 0) < confidence_threshold:
                        # Low confidence score, use fallback method
                        log_operation("🔄 Fallback Analysis", "starting", "low confidence score")
                        device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers)
                        identification_result['device_type'] = device_type
                        identification_result['fallback'] = True
                        log_operation("🔄 Fallback Analysis", "completed", device_type)
                        
                except Exception as e:
                    log_operation("🤖 Smart Device Identification", "error", str(e))
                    print(f"Smart identification error {ip}: {e}")
                    device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers)
                    identification_result = {'device_type': device_type, 'confidence': 0.5, 'error': str(e)}
            else:
                # Simple method
                log_operation("🔍 Simple Device Identification", "starting")
                device_type = self.detect_device_type_smart_enhanced(ip, mac, hostname, vendor, port_numbers)
                identification_result = {'device_type': device_type, 'confidence': 0.5}
                log_operation("🔍 Simple Device Identification", "completed", device_type)
        
        # Device type specific detailed port scan (only in detailed analysis)
        if detailed_analysis and device_type != 'Unknown':
            log_operation("🎯 Device-Specific Port Scan", "starting", f"for {device_type}")
            detailed_ports = self.scan_ports_enhanced(ip, device_type)
            if len(detailed_ports) > len(open_ports):
                open_ports = detailed_ports
                log_operation("🎯 Device-Specific Port Scan", "completed", f"{len(detailed_ports)} additional ports found")
            else:
                log_operation("🎯 Device-Specific Port Scan", "completed", "no new ports found")
        
        # Merge manual ports and enhanced analysis ports while preserving them
        manual_ports = existing_device.get('manual_ports', [])
        enhanced_ports = existing_device.get('all_enhanced_ports', [])
        
        # Add enhanced ports first (detailed analysis results)
        for enhanced_port in enhanced_ports:
            port_exists = False
            enhanced_port_num = enhanced_port.get('port') if isinstance(enhanced_port, dict) else enhanced_port
            
            for existing_port in open_ports:
                existing_port_num = existing_port.get('port') if isinstance(existing_port, dict) else existing_port
                
                if existing_port_num == enhanced_port_num:
                    # If port exists, preserve enhanced information
                    if isinstance(existing_port, dict) and isinstance(enhanced_port, dict):
                        # Preserve enhanced port information as update
                        if enhanced_port.get('description'):
                            existing_port['description'] = enhanced_port['description']
                        if enhanced_port.get('source'):
                            existing_port['source'] = enhanced_port['source']
                        if enhanced_port.get('manual'):
                            existing_port['manual'] = enhanced_port['manual']
                    port_exists = True
                    break
            
            if not port_exists:
                # If enhanced port not found, add it
                open_ports.append(enhanced_port)
                if detailed_analysis:
                    print(f"Enhanced port preserved: {enhanced_port_num} ({ip})")
        
        # Then add manual ports
        for manual_port in manual_ports:
            port_exists = False
            manual_port_num = manual_port.get('port') if isinstance(manual_port, dict) else manual_port
            
            for existing_port in open_ports:
                existing_port_num = existing_port.get('port') if isinstance(existing_port, dict) else existing_port
                
                if existing_port_num == manual_port_num:
                    if isinstance(existing_port, dict):
                        existing_port['manual'] = True
                        # Use manual port description if available
                        if isinstance(manual_port, dict) and manual_port.get('description'):
                            existing_port['description'] = manual_port['description']
                    port_exists = True
                    break
            
            if not port_exists:
                open_ports.append(manual_port)
                print(f"Manual port preserved: {manual_port_num} ({ip})")
        
        # Create device information
        device_info = {
            'ip': ip,
            'mac': mac,
            'hostname': hostname,
            'vendor': vendor,
            'device_type': device_type,
            'open_ports': open_ports,
            'last_seen': datetime.now().isoformat(),
            'status': 'online',
            'alias': existing_device.get('alias', ''),
            'notes': existing_device.get('notes', '')
        }
        
        # Always preserve existing enhanced analysis information
        if existing_device.get('enhanced_comprehensive_info'):
            device_info['enhanced_comprehensive_info'] = existing_device['enhanced_comprehensive_info']
            print(f"Enhanced comprehensive info preserved ({ip})")
        
        if existing_device.get('advanced_scan_summary'):
            device_info['advanced_scan_summary'] = existing_device['advanced_scan_summary']
            print(f"Advanced scan summary preserved ({ip})")
            
        if existing_device.get('last_enhanced_analysis'):
            device_info['last_enhanced_analysis'] = existing_device['last_enhanced_analysis']
            print(f"Last enhanced analysis timestamp preserved ({ip})")
        
        # Always preserve enhanced_info (can be updated in detailed analysis)
        preserve_enhanced_info = existing_device.get('enhanced_info', {})
        if preserve_enhanced_info:
            # Merge existing enhanced_info with new information in detailed analysis
            if detailed_analysis:
                current_enhanced_info = device_info.get('enhanced_info', {})
                current_enhanced_info.update(preserve_enhanced_info)
                device_info['enhanced_info'] = current_enhanced_info
            else:
                # Fully preserve in normal scan
                device_info['enhanced_info'] = preserve_enhanced_info
            print(f"Enhanced info preserved ({ip})")
            
        # Even in non-detailed analysis, preserve important enhanced information
        if not detailed_analysis:
            print(f"🔒 Normal scan - all enhanced information preserved for {ip}")
        
        # Generate smart alias (only in detailed analysis and if no user-defined alias)
        if (smart_naming_enabled and 
            self.smart_naming_config.get('auto_alias', True) and 
            not device_info['alias']):
            try:
                log_operation("🏷️ Auto Alias Generation", "starting")
                smart_alias = self.smart_identifier.generate_smart_alias(
                    device_info, identification_result, enhanced_info
                )
                if smart_alias:
                    device_info['alias'] = smart_alias
                    log_operation("🏷️ Auto Alias Generation", "completed", smart_alias)
                else:
                    log_operation("🏷️ Auto Alias Generation", "completed", "alias not generated")
            except Exception as e:
                log_operation("🏷️ Auto Alias Generation", "error", str(e))
                print(f"Smart alias generation error {ip}: {e}")
        elif local_interface_info and not device_info['alias']:
            # Special alias for local machine
            interface_name = local_interface_info.get('interface_name', 'unknown')
            interface_type = local_interface_info.get('interface_type', 'Other')
            local_hostname = hostname.split(' (')[0]  # Remove parenthesis part
            device_info['alias'] = f"{local_hostname} - {interface_type}"
            print(f"Local machine alias created: {device_info['alias']} ({ip})")
        elif device_info['alias']:
            print(f"User-defined alias preserved: {device_info['alias']} ({ip})")
        
        # Add advanced information (only in detailed analysis)
        if detailed_analysis and enhanced_info:
            # Merge existing enhanced_info and add new information
            current_enhanced_info = device_info.get('enhanced_info', {})
            current_enhanced_info.update({
                'hostname_resolution': enhanced_hostname_info,
                'identification_result': identification_result,
                'advanced_scan_summary': {
                    'methods_used': list(enhanced_info.keys()),
                    'confidence': identification_result.get('confidence', 0),
                    'smart_naming_used': smart_naming_enabled
                }
            })
            device_info['enhanced_info'] = current_enhanced_info
        
        # Log device analysis completion
        if detailed_analysis and progress_callback:
            alias_info = f" - Alias: {device_info.get('alias', 'N/A')}" if device_info.get('alias') else ""
            ports_info = f" - {len(device_info.get('open_ports', []))} ports"
            smart_info = " - 🧠 Smart Analysis" if device_info.get('enhanced_info') else ""
            progress_callback(f"✅ {ip} analysis completed: {device_info.get('device_type', 'Unknown')}{alias_info}{ports_info}{smart_info}")
        
        return device_info
    
    def scan_network(self, progress_callback=None, ip_range=None, include_offline=None):
        """Scans the entire network"""
        self.scanning = True
        
        # Load existing device information to preserve (using unified model)
        existing_devices = {}
        if os.path.exists('data/lan_devices.json'):
            try:
                with open('data/lan_devices.json', 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    # Index existing devices by MAC+IP combination and migrate to unified format
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        ip = device.get('ip', '')
                        if mac and ip:
                            # MAC+IP combination key
                            device_key = f"{mac}@{ip}"
                            # Migrate from legacy format to unified format
                            unified_device = unified_model.migrate_legacy_data(device)
                            existing_devices[device_key] = unified_device
                            print(f"📤 Legacy data migrated: {ip} (MAC: {mac}) - {unified_device.get('alias', 'N/A')}")
            except Exception as e:
                print(f"Error loading existing device information: {e}")
        
        self.devices = []
        start_time = datetime.now()
        
        # Get settings from config
        if ip_range is None:
            ip_range = self.get_local_network()
        if include_offline is None:
            include_offline = self.scan_settings.get('include_offline', False)
        
        print(f"Network to be scanned: {ip_range}")
        
        if progress_callback:
            progress_callback("Starting ARP scan...")
        
        # Quick scan with ARP
        arp_devices = self.scan_network_arp(ip_range)
        
        # Add local machine interfaces
        local_interfaces = self.get_local_machine_interfaces()
        local_hostname = self.get_local_machine_hostname()
        
        # Add local machine IPs to ARP results
        for interface in local_interfaces:
            # Check if this IP is already found in ARP scan
            ip_found = False
            for arp_device in arp_devices:
                if arp_device['ip'] == interface['ip']:
                    ip_found = True
                    break
            
            if not ip_found:
                # Add local machine IP
                arp_devices.append({
                    'ip': interface['ip'],
                    'mac': interface['mac'],
                    'local_interface': True,
                    'interface_name': interface['interface'],
                    'interface_type': interface['type']
                })
                print(f"🖥️ Local machine interface added: {interface['ip']} (MAC: {interface['mac']}, Interface: {interface['interface']})")
        
        total_devices = len(arp_devices)
        
        if progress_callback:
            progress_callback(f"{total_devices} devices found (including local machine), starting detailed scan...")
        
        # For statistics
        device_types = {}
        vendors = {}
        online_count = 0
        
        # Detailed scan for each device
        for i, device in enumerate(arp_devices):
            if not self.scanning:  # If scanning is stopped
                break
                
            if progress_callback:
                progress_callback(f"Scanning: {device['ip']} ({i+1}/{total_devices})")
            
            try:
                # Prepare local machine information
                local_interface_info = None
                if device.get('local_interface'):
                    local_interface_info = {
                        'interface_name': device.get('interface_name'),
                        'interface_type': device.get('interface_type'),
                        'is_local': True
                    }
                
                # Scan device using unified model
                new_device_info = self.scan_single_device(
                    device['ip'], 
                    device['mac'], 
                    existing_devices, 
                    detailed_analysis=False, 
                    progress_callback=progress_callback,
                    local_interface_info=local_interface_info
                )
                
                # MAC+IP combination key
                current_mac = device['mac'].lower()
                current_ip = device['ip']
                device_key = f"{current_mac}@{current_ip}"
                
                # Search for existing device by MAC+IP combination
                existing_device = existing_devices.get(device_key)
                
                if existing_device:
                    # Existing device - merge with unified model
                    merged_device = unified_model.merge_device_data(existing_device, new_device_info, "normal_scan")
                    self.devices.append(merged_device)
                    print(f"🔄 Unified merge: {current_ip} (MAC: {current_mac}) - {merged_device.get('alias', 'N/A')}")
                else:
                    # New device - convert to unified format
                    unified_device = unified_model.migrate_legacy_data(new_device_info)
                    self.devices.append(unified_device)
                    print(f"🆕 New unified device: {current_ip} (MAC: {current_mac}) - {unified_device.get('alias', 'N/A')}")
                
                # Statistics - use the last added device
                online_count += 1
                current_device = self.devices[-1]  # Last added device
                device_type = current_device['device_type']
                vendor = current_device['vendor']
                
                device_types[device_type] = device_types.get(device_type, 0) + 1
                vendors[vendor] = vendors.get(vendor, 0) + 1
                
            except Exception as e:
                print(f"Device scan error {device['ip']}: {e}")
        
        # ALWAYS check existing devices to preserve (regardless of include_offline setting)
        # Preserve all devices with user-defined information
        current_macs = {device['mac'].lower() for device in self.devices}
        
        # Add offline devices from existing devices that have valuable information
        preserved_count = 0
        current_device_keys = {f"{device['mac'].lower()}@{device['ip']}" for device in self.devices}
        
        for device_key, unified_device in existing_devices.items():
            # This device was not found in the current scan but has valuable information
            if device_key not in current_device_keys:
                # Check preservation criteria with unified model
                should_preserve = (
                    unified_device.get('alias') or
                    unified_device.get('notes') or 
                    unified_device.get('device_type') or
                    unified_device.get('open_ports') or
                    unified_device.get('analysis_data', {}).get('enhanced_analysis_info') or
                    unified_device.get('analysis_data', {}).get('normal_scan_info') or
                    # Also check for legacy fields
                    unified_device.get('enhanced_comprehensive_info') or
                    unified_device.get('enhanced_info') or
                    unified_device.get('advanced_scan_summary')
                )
                
                if should_preserve:
                    # Mark the device as offline and add it
                    unified_device['status'] = 'offline'
                    unified_device['last_seen'] = unified_device.get('last_seen', datetime.now().isoformat())
                    self.devices.append(unified_device)
                    preserved_count += 1
                    print(f"📴 Offline device preserved: {unified_device.get('ip', 'N/A')} (MAC: {unified_device.get('mac', 'N/A')}) - {unified_device.get('alias', 'N/A')}")
        
        if preserved_count > 0:
            print(f"✅ {preserved_count} offline devices preserved")
        
        # Final MAC+IP duplicate check and cleanup
        print(f"\n🔍 Final MAC+IP duplicate check...")
        unique_devices = []
        seen_device_keys = set()
        
        for device in self.devices:
            mac = device.get('mac', '').lower()
            ip = device.get('ip', '')
            device_key = f"{mac}@{ip}"
            
            if device_key in seen_device_keys:
                print(f"⚠️ Duplicate MAC+IP detected: {device_key} - skipping")
                continue
            
            seen_device_keys.add(device_key)
            unique_devices.append(device)
        
        if len(unique_devices) != len(self.devices):
            self.devices = unique_devices
            print(f"🧹 {len(self.devices)} unique devices remain (MAC+IP duplicates removed)")
        else:
            print(f"✅ All devices are unique - {len(self.devices)} devices (based on MAC+IP)")
        
        scan_duration = (datetime.now() - start_time).total_seconds()
        
        # Save to scan history
        scan_data = {
            'total_devices': len(self.devices),
            'online_devices': online_count,
            'ip_range': ip_range,
            'scan_duration': scan_duration,
            'device_types': device_types,
            'vendors': vendors
        }
        
        self.config_manager.add_scan_history(scan_data)
        
        # Also scan Docker containers
        if progress_callback:
            progress_callback("Detecting Docker containers...")
        
        try:
            docker_devices = self.scan_docker_containers_directly()
            if docker_devices:
                # Add Docker containers to the current device list
                existing_ips = {device['ip'] for device in self.devices}
                
                for docker_device in docker_devices:
                    # Do not add the same IP again
                    if docker_device['ip'] not in existing_ips:
                        self.devices.append(docker_device)
                        
                        # Update statistics
                        device_type = docker_device['device_type']
                        vendor = docker_device['vendor']
                        device_types[device_type] = device_types.get(device_type, 0) + 1
                        vendors[vendor] = vendors.get(vendor, 0) + 1
                        online_count += 1
                
                # Save updated statistics
                scan_data = {
                    'total_devices': len(self.devices),
                    'online_devices': online_count,
                    'ip_range': ip_range,
                    'scan_duration': scan_duration,
                    'device_types': device_types,
                    'vendors': vendors
                }
                self.config_manager.add_scan_history(scan_data)
                
                if progress_callback:
                    progress_callback(f"{len(docker_devices)} Docker containers added.")
                    
        except Exception as e:
            print(f"Docker container scan error: {e}")
        
        self.scanning = False
        if progress_callback:
            progress_callback(f"Scan completed! {len(self.devices)} devices found.")
        
        return self.devices
    
    def stop_scan(self):
        """Stops the scan"""
        self.scanning = False
    
    def save_to_json(self, filename='data/lan_devices.json'):
        """Saves device information to a JSON file (with credentials encrypted)"""
        try:
            # Create directory if it does not exist
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            
            # Copy device data and encrypt credentials
            devices_to_save = []
            for device in self.devices:
                device_copy = device.copy()
                
                # Get credential information and encrypt it
                ip = device.get('ip')
                if ip:
                    stored_credentials = self.credential_manager.get_device_credentials(ip)
                    if stored_credentials:
                        # Save credentials with simple encryption
                        device_copy['encrypted_credentials'] = self._encrypt_credentials_simple(stored_credentials)
                
                devices_to_save.append(device_copy)
            
            # Sanitize sensitive data
            sanitized_devices = self.data_sanitizer.sanitize_device_data(devices_to_save)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(sanitized_devices, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            print(f"JSON save error: {e}")
            return False
    
    def save_devices(self, filename='data/lan_devices.json'):
        """Saves devices - redirects to save_to_json"""
        return self.save_to_json(filename)
    
    def load_from_json(self, filename='data/lan_devices.json'):
        """Loads device information from a JSON file (decodes encrypted credentials)"""
        try:
            if os.path.exists(filename):
                with open(filename, 'r', encoding='utf-8') as f:
                    loaded_devices = json.load(f)
                
                # Decrypt credentials and save to credential manager
                for device in loaded_devices:
                    if 'encrypted_credentials' in device:
                        ip = device.get('ip')
                        if ip:
                            decrypted_creds = self._decrypt_credentials_simple(device['encrypted_credentials'])
                            if decrypted_creds:
                                # Save to credential manager
                                for access_type, creds in decrypted_creds.items():
                                    self.credential_manager.save_device_credentials(
                                        ip, access_type, 
                                        creds.get('username'),
                                        creds.get('password'),
                                        creds.get('port'),
                                        creds.get('additional_info')
                                    )
                        
                        # Preserve encrypted credentials in the device (do not delete!)
                        # del device['encrypted_credentials']  # This line is commented
                
                self.devices = loaded_devices
                return True
            else:
                # If main file does not exist, load sample file
                sample_filename = 'data/lan_devices_sample.json'
                if os.path.exists(sample_filename):
                    print(f"Main file not found, loading sample data: {sample_filename}")
                    return self.load_from_json(sample_filename)
                else:
                    print(f"File not found: {filename}")
                    return False
        except Exception as e:
            print(f"JSON load error: {e}")
            return False
    
    def _encrypt_credentials_simple(self, credentials):
        """Encrypts credentials with simple base64 encoding"""
        try:
            if not credentials:
                return None
            
            # Convert to JSON string and base64 encode
            json_str = json.dumps(credentials)
            encoded_bytes = base64.b64encode(json_str.encode('utf-8'))
            return encoded_bytes.decode('utf-8')
        except Exception as e:
            print(f"Credential encryption error: {e}")
            return None
    
    def _decrypt_credentials_simple(self, encrypted_data):
        """Decrypts base64 encoded credentials"""
        try:
            if not encrypted_data:
                return None
            
            # If new format (dict), it will be processed by the credential manager, skip it
            if isinstance(encrypted_data, dict):
                print(f"🔧 New credential format detected, will be processed by credential manager")
                return None
            
            # If old format (string), base64 decode it
            if isinstance(encrypted_data, str):
                # Base64 decode and parse JSON
                decoded_bytes = base64.b64decode(encrypted_data.encode('utf-8'))
                json_str = decoded_bytes.decode('utf-8')
                return json.loads(json_str)
            
            print(f"⚠️ Unexpected credential data type: {type(encrypted_data)}")
            return None
            
        except Exception as e:
            print(f"Credential decryption error: {e}")
            return None
    
    def update_device(self, ip, updates):
        """Updates information for a specific device"""
        for i, device in enumerate(self.devices):
            if device['ip'] == ip:
                # Check for IP and MAC changes
                new_ip = updates.get('ip', device['ip'])
                new_mac = updates.get('mac', device['mac'])
                
                # If IP or MAC changes, create a new device key
                old_device_key = f"{device['mac'].lower()}@{device['ip']}"
                new_device_key = f"{new_mac.lower()}@{new_ip}"
                
                if old_device_key != new_device_key:
                    print(f"📍 Device key change: {old_device_key} -> {new_device_key}")
                    
                    # Check if the new device key conflicts
                    for other_device in self.devices:
                        if other_device != device:
                            other_key = f"{other_device['mac'].lower()}@{other_device['ip']}"
                            if other_key == new_device_key:
                                print(f"❌ Device key conflict: {new_device_key} already exists")
                                return False
                
                print(f"🔄 Updating device: {device['ip']} -> {new_ip} (MAC: {device['mac']} -> {new_mac})")
                # Handle manual ports
                if 'manual_ports' in updates:
                    manual_ports = updates.pop('manual_ports')  # Remove from updates
                    
                    # Preserve current open_ports (automatically scanned ports)
                    current_open_ports = device.get('open_ports', [])
                    
                    # Add manual ports to open_ports
                    for manual_port in manual_ports:
                        port_num = manual_port['port']
                        port_desc = manual_port['description']
                        
                        # Check if this port already exists
                        port_exists = False
                        for existing_port in current_open_ports:
                            if isinstance(existing_port, dict) and existing_port.get('port') == port_num:
                                # Update existing port
                                existing_port['description'] = port_desc
                                existing_port['manual'] = True
                                port_exists = True
                                break
                            elif isinstance(existing_port, int) and existing_port == port_num:
                                # Old format (int only), convert to new format
                                current_open_ports.remove(existing_port)
                                current_open_ports.append({
                                    'port': port_num,
                                    'description': port_desc,
                                    'manual': True
                                })
                                port_exists = True
                                break
                        
                        # If port does not exist, add it
                        if not port_exists:
                            current_open_ports.append({
                                'port': port_num,
                                'description': port_desc,
                                'manual': True
                            })
                    
                    # Save updated port list
                    device['open_ports'] = current_open_ports
                
                # Apply other updates
                device.update(updates)
                return True
        return False
    
    def get_devices(self):
        """Returns all devices"""
        return self.devices
    
    def get_config_manager(self):
        """Returns the config manager"""
        return self.config_manager
    
    def get_oui_manager(self):
        """Returns the OUI manager"""
        return self.oui_manager
    
    def perform_detailed_analysis(self, progress_callback=None):
        """Performs parallel detailed analysis for existing devices"""
        if not self.devices:
            if progress_callback:
                progress_callback("A scan must be performed first for detailed analysis!")
            return
        
        if progress_callback:
            progress_callback("🚀 Starting parallel detailed analysis...")
        
        # Load existing device information to preserve
        existing_devices = {}
        if os.path.exists('data/lan_devices.json'):
            try:
                with open('data/lan_devices.json', 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        if mac:
                            existing_devices[mac] = {
                                'alias': device.get('alias', ''),
                                'notes': device.get('notes', ''),
                                'device_type': device.get('device_type', ''),
                                'manual_ports': [p for p in device.get('open_ports', []) if p.get('manual', False)]
                            }
            except Exception as e:
                print(f"Error loading existing device information: {e}")
        
        # Get online devices
        online_devices = [d for d in self.devices if d.get('status') == 'online']
        offline_devices = [d for d in self.devices if d.get('status') != 'online']
        total_devices = len(online_devices)
        
        if progress_callback:
            progress_callback(f"📊 {total_devices} online devices, {len(offline_devices)} offline devices detected")
        
        analyzed_devices = []
        completed_count = 0
        analysis_lock = threading.Lock()
        
        def analyze_single_device(device, device_index):
            nonlocal completed_count
            try:
                # Thread-safe progress update
                with analysis_lock:
                    completed_count += 1
                    if progress_callback:
                        progress_callback(f"🔍 Starting analysis: {device['ip']} ({completed_count}/{total_devices})")
                
                # Perform detailed analysis
                detailed_device = self.scan_single_device(
                    device['ip'], 
                    device['mac'], 
                    existing_devices, 
                    detailed_analysis=True,
                    progress_callback=progress_callback,
                    local_interface_info=None  # No local machine info in detailed analysis
                )
                
                # Add analysis results to device information
                detailed_device = self.enhance_device_with_analysis_results(detailed_device)
                
                return detailed_device
                
            except Exception as e:
                print(f"Detailed analysis error {device['ip']}: {e}")
                # Preserve old device information in case of error
                return device
        
        # Use ThreadPoolExecutor for parallel processing
        max_workers = min(4, len(online_devices))  # Maximum 4 threads
        
        if progress_callback:
            progress_callback(f"🛠️ Starting analysis with {max_workers} parallel threads...")
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Start analysis tasks for all devices
            future_to_device = {
                executor.submit(analyze_single_device, device, i): device 
                for i, device in enumerate(online_devices)
            }
            
            # Wait for results and collect them
            for future in as_completed(future_to_device):
                device = future_to_device[future]
                try:
                    analyzed_device = future.result()
                    analyzed_devices.append(analyzed_device)
                except Exception as e:
                    print(f"Thread error {device['ip']}: {e}")
                    analyzed_devices.append(device)
        
        # Add offline devices
        analyzed_devices.extend(offline_devices)
        
        # Update device list
        self.devices = analyzed_devices
        
        # Save to JSON
        self.save_to_json()
        
        if progress_callback:
            progress_callback(f"✅ Parallel detailed analysis completed! {total_devices} devices analyzed with {max_workers} threads.")
    
    def enhance_device_with_analysis_results(self, device):
        """Adds analysis results to device information"""
        enhanced_info = device.get('enhanced_info', {})
        
        # Add detailed information for open ports
        if device.get('open_ports'):
            enhanced_ports_info = []
            for port in device['open_ports']:
                if isinstance(port, dict):
                    port_num = port.get('port')
                    service = port.get('service', '')
                    version = port.get('version', '')
                    
                    if port_num:
                        port_detail = f"Port {port_num}"
                        if service:
                            port_detail += f" ({service})"
                        if version:
                            port_detail += f" - {version}"
                        enhanced_ports_info.append(port_detail)
            
            # Port information is stored in open_ports array, not added to notes
        
        # Add gathered information to notes
        if enhanced_info:
            current_notes = device.get('notes', '')
            
            # OS information
            if enhanced_info.get('ping_analysis', {}).get('os_guess'):
                os_info = enhanced_info['ping_analysis']['os_guess']
                os_text = f"\n\n💻 Operating System: {os_info}"
                if "💻 Operating System:" not in current_notes:
                    device['notes'] = device.get('notes', '') + os_text
            
            # Web information
            web_info = enhanced_info.get('web_info', {})
            if web_info.get('server_header') or web_info.get('title'):
                web_text = "\n\n🌍 Web Information:"
                if web_info.get('title'):
                    web_text += f"\n  • Title: {web_info['title']}"
                if web_info.get('server_header'):
                    web_text += f"\n  • Server: {web_info['server_header']}"
                
                if "🌍 Web Information:" not in current_notes:
                    device['notes'] = device.get('notes', '') + web_text
            
            # SNMP information
            snmp_info = enhanced_info.get('snmp_info', {})
            if snmp_info.get('system_name') or snmp_info.get('system_description'):
                snmp_text = "\n\n📡 SNMP Information:"
                if snmp_info.get('system_name'):
                    snmp_text += f"\n  • System Name: {snmp_info['system_name']}"
                if snmp_info.get('system_description'):
                    snmp_text += f"\n  • Description: {snmp_info['system_description']}"
                
                if "📡 SNMP Information:" not in current_notes:
                    device['notes'] = device.get('notes', '') + snmp_text
        
        # Update alias (only if not user-defined)
        current_alias = device.get('alias', '')
        # If the current alias is auto-generated or empty, update it
        is_auto_generated = (
            not current_alias or 
            not current_alias.strip() or
            'XEROX CORPORATION' in current_alias or
            'Unknown Device' in current_alias
        )
        
        if is_auto_generated:
            # Create new alias
            device_type = device.get('device_type', '')
            vendor = device.get('vendor', '')
            hostname = device.get('hostname', '')
            
            alias_parts = []
            if vendor and vendor != 'Unknown' and 'XEROX' not in vendor:
                alias_parts.append(vendor.split()[0])  # First word
            if device_type and device_type != 'Unknown':
                alias_parts.append(device_type)
            if hostname and hostname != device.get('ip', '') and hostname:
                alias_parts.append(hostname.split('.')[0])  # First part
            
            if alias_parts:
                device['alias'] = ' '.join(alias_parts[:2])  # Maximum 2 words
            elif hostname and hostname != device.get('ip', ''):
                device['alias'] = hostname.split('.')[0]
        
        return device
    
    def perform_single_device_detailed_analysis(self, ip_address, progress_callback=None):
        """Performs detailed analysis for a single device"""
        if progress_callback:
            progress_callback(f"Starting detailed device analysis: {ip_address}")
        
        # Find the device in the list
        target_device = None
        device_index = -1
        for i, device in enumerate(self.devices):
            if device.get('ip') == ip_address:
                target_device = device
                device_index = i
                break
        
        if not target_device:
            if progress_callback:
                progress_callback(f"Device not found: {ip_address}")
            return
        
        # Load existing device information to preserve
        existing_devices = {}
        if os.path.exists('data/lan_devices.json'):
            try:
                with open('data/lan_devices.json', 'r', encoding='utf-8') as f:
                    old_devices = json.load(f)
                    for device in old_devices:
                        mac = device.get('mac', '').lower()
                        if mac:
                            existing_devices[mac] = {
                                'alias': device.get('alias', ''),
                                'notes': device.get('notes', ''),
                                'device_type': device.get('device_type', ''),
                                'manual_ports': [p for p in device.get('open_ports', []) if p.get('manual', False)]
                            }
            except Exception as e:
                print(f"Error loading existing device information: {e}")
        
        try:
            # Perform detailed analysis
            detailed_device = self.scan_single_device(
                target_device['ip'], 
                target_device['mac'], 
                existing_devices, 
                detailed_analysis=True,
                progress_callback=progress_callback,
                local_interface_info=None  # No local machine info in single device detailed analysis
            )
            
            # Add analysis results to device information
            detailed_device = self.enhance_device_with_analysis_results(detailed_device)
            
            # Update the device in the list
            self.devices[device_index] = detailed_device
            
            # Save to JSON
            self.save_to_json()
            
            if progress_callback:
                progress_callback(f"Detailed analysis completed: {ip_address}")
                
        except Exception as e:
            error_msg = f"Detailed analysis error {ip_address}: {e}"
            print(error_msg)
            if progress_callback:
                progress_callback(error_msg)

if __name__ == "__main__":
    # For testing purposes
    scanner = LANScanner()
    print("Starting LAN scan...")
    devices = scanner.scan_network()
    
    print(f"\n{len(devices)} devices found:")
    for device in devices:
        print(f"IP: {device['ip']}, MAC: {device['mac']}, "
              f"Hostname: {device['hostname']}, Vendor: {device['vendor']}, "
              f"Type: {device['device_type']}")
        if device['open_ports']:
            ports = ', '.join([f"{p['port']}/{p['service']}" for p in device['open_ports']])
            print(f"  Open ports: {ports}")
    
    # Save to JSON
    scanner.save_to_json()
    print("\nInformation saved to lan_devices.json.")
