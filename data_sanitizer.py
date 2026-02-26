#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Data sanitizer for LAN Scanner - removes sensitive information from device data
"""

import json
import re
import copy
from typing import Dict, List, Any

class DataSanitizer:
    """Removes sensitive information from device data"""
    
    def __init__(self):
        # Sensitive header names (case-insensitive)
        self.sensitive_headers = {
            'set-cookie', 'cookie', 'authorization', 'x-csrf-token', 
            'csrf-token', 'x-xsrf-token', 'xsrf-token', 'x-auth-token', 'x-api-key',
            'api-key', 'x-session-id', 'session-id'
        }
        
        # Sensitive fields
        self.sensitive_fields = {
            'password', 'pass', 'pwd', 'secret', 'key', 'token', 
            'session', 'cookie', 'auth', 'credential'
        }
        
        # File extensions to be sanitized
        self.asset_extensions = {
            '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot'
        }
        
    def sanitize_device_data(self, devices: List[Dict]) -> List[Dict]:
        """Sanitizes sensitive data in the device list"""
        sanitized_devices = []
        
        for device in devices:
            sanitized_device = self._sanitize_single_device(copy.deepcopy(device))
            sanitized_devices.append(sanitized_device)
            
        return sanitized_devices
    
    def _sanitize_single_device(self, device: Dict) -> Dict:
        """Sanitizes data of a single device"""
        # Legacy format fields
        if 'enhanced_info' in device and device['enhanced_info']:
            device['enhanced_info'] = self._sanitize_enhanced_info(device['enhanced_info'])
        
        if 'enhanced_comprehensive_info' in device and device['enhanced_comprehensive_info']:
            device['enhanced_comprehensive_info'] = self._sanitize_enhanced_info(device['enhanced_comprehensive_info'])
        
        if 'advanced_scan_summary' in device and device['advanced_scan_summary']:
            device['advanced_scan_summary'] = self._sanitize_enhanced_info(device['advanced_scan_summary'])
        
        # Unified format fields
        if 'analysis_data' in device and device['analysis_data']:
            analysis_data = device['analysis_data']
            
            if 'normal_scan_info' in analysis_data and analysis_data['normal_scan_info']:
                analysis_data['normal_scan_info'] = self._sanitize_enhanced_info(analysis_data['normal_scan_info'])
                
            if 'enhanced_analysis_info' in analysis_data and analysis_data['enhanced_analysis_info']:
                analysis_data['enhanced_analysis_info'] = self._sanitize_enhanced_info(analysis_data['enhanced_analysis_info'])
        
        # Sanitize top-level web services info
        if 'web_services' in device and device['web_services']:
            device['web_services'] = self._sanitize_web_services(device['web_services'])
            
        return device
    
    def _sanitize_enhanced_info(self, enhanced_info: Dict) -> Dict:
        """Sanitizes the enhanced info section"""
        sanitized = copy.deepcopy(enhanced_info)
        
        # Sanitize web services
        if 'web_services' in sanitized:
            sanitized['web_services'] = self._sanitize_web_services(sanitized['web_services'])
            
        return sanitized
    
    def _sanitize_web_services(self, web_services: Dict) -> Dict:
        """Sanitizes web service information"""
        sanitized = {}
        
        for service_key, service_data in web_services.items():
            if isinstance(service_data, dict):
                sanitized_service = self._sanitize_service_data(service_data)
                # Add if not empty after sanitization
                if sanitized_service:
                    sanitized[service_key] = sanitized_service
            else:
                sanitized[service_key] = service_data
                
        return sanitized
    
    def _sanitize_service_data(self, service_data: Dict) -> Dict:
        """Sanitizes data of a single service"""
        sanitized = {}
        
        for key, value in service_data.items():
            if key.lower() == 'headers' and isinstance(value, dict):
                # Sanitize headers
                clean_headers = self._sanitize_headers(value)
                if clean_headers:
                    sanitized[key] = clean_headers
            elif key.lower() == 'links' and isinstance(value, list):
                # Sanitize links
                clean_links = self._sanitize_links(value)
                if clean_links:
                    sanitized[key] = clean_links
            elif not self._is_sensitive_field(key):
                # Check other fields
                sanitized[key] = value
                
        return sanitized
    
    def _sanitize_headers(self, headers: Dict) -> Dict:
        """Sanitizes HTTP headers"""
        clean_headers = {}
        
        for header_name, header_value in headers.items():
            if not self._is_sensitive_header(header_name):
                # Also sanitize if header value contains token, session, etc.
                if not self._is_sensitive_header_value(header_value):
                    clean_headers[header_name] = header_value
                
        return clean_headers
    
    def _is_sensitive_header_value(self, header_value: str) -> bool:
        """Checks if the header value contains sensitive data"""
        if not isinstance(header_value, str):
            return False
            
        value_lower = header_value.lower()
        sensitive_patterns = [
            'xsrf-token=', 'csrf-token=', 'session=', '_token=',
            'laravel_session=', 'phpsessid=', 'jsessionid='
        ]
        
        return any(pattern in value_lower for pattern in sensitive_patterns)
    
    def _sanitize_links(self, links: List) -> List:
        """Sanitizes the list of links"""
        clean_links = []
        
        for link in links:
            if isinstance(link, str):
                # Filter data URIs (data:image/, data:application/, etc.)
                if link.startswith('data:'):
                    continue
                # Filter asset files
                if not self._is_asset_file(link):
                    # Filter Docker overlay paths
                    if not self._is_docker_overlay_path(link):
                        clean_links.append(link)
            else:
                clean_links.append(link)
                
        return clean_links
    
    def _is_sensitive_header(self, header_name: str) -> bool:
        """Checks if the header is sensitive"""
        return header_name.lower() in self.sensitive_headers
    
    def _is_sensitive_field(self, field_name: str) -> bool:
        """Checks if the field is sensitive"""
        field_lower = field_name.lower()
        return any(sensitive in field_lower for sensitive in self.sensitive_fields)
    
    def _is_asset_file(self, link: str) -> bool:
        """Checks if the link is an asset file"""
        link_lower = link.lower()
        
        # Check by file extension
        for ext in self.asset_extensions:
            if ext in link_lower:
                return True
                
        # Check by path patterns
        asset_patterns = [
            r'/images?/',
            r'/css/',
            r'/js/',
            r'/assets?/',
            r'/static/',
            r'/media/',
            r'/fonts?/',
            r'\.css\?',
            r'\.js\?'
        ]
        
        for pattern in asset_patterns:
            if re.search(pattern, link_lower):
                return True
                
        return False
    
    def _is_docker_overlay_path(self, link: str) -> bool:
        """Checks if the link is a Docker overlay path"""
        docker_patterns = [
            r'/var/lib/docker/overlay',
            r'/overlay/',
            r'docker/overlay',
            r'overlay\d+/',
        ]
        
        for pattern in docker_patterns:
            if re.search(pattern, link, re.IGNORECASE):
                return True
                
        return False
    
    def sanitize_file(self, input_file: str, output_file: str = None) -> bool:
        """Sanitizes the file"""
        try:
            # Read the file
            with open(input_file, 'r', encoding='utf-8') as f:
                devices = json.load(f)
            
            # Sanitize
            sanitized_devices = self.sanitize_device_data(devices)
            
            # If output file is not specified, write to the same file
            if output_file is None:
                output_file = input_file
            
            # Write sanitized data
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(sanitized_devices, f, indent=2, ensure_ascii=False)
            
            return True
            
        except Exception as e:
            print(f"File sanitization error: {e}")
            return False
    
    def get_sanitization_stats(self, original_devices: List[Dict], sanitized_devices: List[Dict]) -> Dict:
        """Returns sanitization statistics"""
        stats = {
            'total_devices': len(original_devices),
            'headers_removed': 0,
            'links_removed': 0,
            'fields_removed': 0
        }
        
        # These statistics are only approximate
        # In a real implementation, more detailed counting can be done
        
        return stats

def main():
    """Test function"""
    sanitizer = DataSanitizer()
    
    # Sanitize lan_devices.json file for test
    input_file = 'data/lan_devices.json'
    backup_file = 'data/lan_devices_backup.json'
    
    # First, take backup
    import shutil
    try:
        shutil.copy2(input_file, backup_file)
        print(f"Backup created: {backup_file}")
        
        # Sanitize file
        if sanitizer.sanitize_file(input_file):
            print(f"File sanitized: {input_file}")
        else:
            print("File sanitization failed!")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()