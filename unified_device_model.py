#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unified Device Model - Common JSON schema and data model
Unified data structure for Normal Scan and Enhanced Analysis
"""

import json
from datetime import datetime
from typing import Dict, List, Any, Optional

class UnifiedDeviceModel:
    """
    Unified Device Model - Common data model for all scan methods
    """
    
    def __init__(self):
        self.unified_schema = {
            # Core device information
            "ip": "",
            "mac": "",
            "hostname": "",
            "vendor": "",
            "device_type": "",
            "status": "online",  # online, offline
            "last_seen": "",
            
            # User-defined information
            "alias": "",
            "notes": "",
            
            # Unified port structure
            "open_ports": [],
            
            # Unified analysis data container
            "analysis_data": {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            },
            
            # Backward compatibility fields
            "enhanced_info": None,
            "enhanced_comprehensive_info": None,
            "advanced_scan_summary": None,
            "last_enhanced_analysis": None
        }
    
    def create_unified_device(self, ip: str, mac: str, **kwargs) -> Dict[str, Any]:
        """Create unified device object"""
        device = self.unified_schema.copy()
        device.update({
            "ip": ip,
            "mac": mac,
            "last_seen": datetime.now().isoformat(),
            "analysis_data": {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            }
        })
        
        # Add additional parameters
        for key, value in kwargs.items():
            if key in device:
                device[key] = value
        
        return device
    
    def create_unified_port(self, port: int, **kwargs) -> Dict[str, Any]:
        """Create unified port object"""
        port_obj = {
            "port": port,
            "service": kwargs.get("service", "unknown"),
            "state": kwargs.get("state", "open"),
            "version": kwargs.get("version", ""),
            "product": kwargs.get("product", ""),
            "description": kwargs.get("description", ""),
            "manual": kwargs.get("manual", False),
            "source": kwargs.get("source", "port_scan"),  # normal_scan, enhanced_analysis, manual
            "last_verified": datetime.now().isoformat()
        }
        return port_obj
    
    def merge_device_data(self, existing_device: Dict[str, Any], new_device: Dict[str, Any], 
                         scan_type: str = "normal_scan") -> Dict[str, Any]:
        """
        Merge existing device data with new scan results
        scan_type: "normal_scan" or "enhanced_analysis"
        """
        if not existing_device:
            return new_device
        
        # Check MAC+IP combination
        existing_mac = existing_device.get('mac', '').lower()
        new_mac = new_device.get('mac', '').lower()
        existing_ip = existing_device.get('ip', '')
        new_ip = new_device.get('ip', '')
        
        # MAC+IP combination must be the same for merge
        if existing_mac != new_mac or existing_ip != new_ip:
            print(f"⚠️ MAC+IP mismatch: {existing_mac}@{existing_ip} != {new_mac}@{new_ip} - different devices, not merging")
            return new_device
        
        print(f"🔄 MAC+IP match: {existing_mac}@{existing_ip} - merging data")
        
        # Update core information
        merged = existing_device.copy()
        
        # Update core fields (preserving IP and MAC)
        core_fields = ["hostname", "vendor", "status", "last_seen"]
        for field in core_fields:
            if field in new_device and new_device[field]:
                merged[field] = new_device[field]
        
        # Preserve user-defined fields - Prefer existing values
        user_fields = ["alias", "notes", "device_type"]
        for field in user_fields:
            if field in existing_device and existing_device[field]:
                # If existing value, keep it (user-defined)
                merged[field] = existing_device[field]
            elif field in new_device and new_device[field]:
                # If no existing value, use new value
                merged[field] = new_device[field]
            else:
                # If neither has value, set to empty string
                merged[field] = ""
        
        # Update analysis data
        if "analysis_data" not in merged:
            merged["analysis_data"] = {
                "last_normal_scan": None,
                "last_enhanced_analysis": None,
                "normal_scan_info": {},
                "enhanced_analysis_info": {}
            }
        
        # Update analysis data by scan type
        if scan_type == "normal_scan":
            merged["analysis_data"]["last_normal_scan"] = datetime.now().isoformat()
            if "analysis_data" in new_device and "normal_scan_info" in new_device["analysis_data"]:
                merged["analysis_data"]["normal_scan_info"] = new_device["analysis_data"]["normal_scan_info"]
        elif scan_type == "enhanced_analysis":
            merged["analysis_data"]["last_enhanced_analysis"] = datetime.now().isoformat()
            if "analysis_data" in new_device and "enhanced_analysis_info" in new_device["analysis_data"]:
                merged["analysis_data"]["enhanced_analysis_info"] = new_device["analysis_data"]["enhanced_analysis_info"]
        
        # Merge ports
        merged["open_ports"] = self.merge_ports(
            existing_device.get("open_ports", []),
            new_device.get("open_ports", []),
            scan_type
        )
        
        # Preserve encrypted credentials (very important!)
        if "encrypted_credentials" in existing_device:
            merged["encrypted_credentials"] = existing_device["encrypted_credentials"]
        
        return merged
    
    def merge_ports(self, existing_ports: List[Dict], new_ports: List[Dict], 
                   scan_type: str) -> List[Dict]:
        """Merge port lists"""
        merged_ports = {}
        
        # Add existing ports
        for port in existing_ports:
            port_num = port.get("port")
            if port_num:
                merged_ports[port_num] = port.copy()
        
        # Add/update new ports
        for port in new_ports:
            port_num = port.get("port")
            if port_num:
                if port_num in merged_ports:
                    # Update existing port
                    existing_port = merged_ports[port_num]
                    
                    # Preserve manual ports
                    if existing_port.get("manual", False):
                        continue
                    
                    # Preserve more detailed information
                    if port.get("version") and not existing_port.get("version"):
                        existing_port["version"] = port["version"]
                    if port.get("product") and not existing_port.get("product"):
                        existing_port["product"] = port["product"]
                    if port.get("description") and not existing_port.get("description"):
                        existing_port["description"] = port["description"]
                    
                    # Update source
                    existing_port["source"] = port.get("source", scan_type)
                    existing_port["last_verified"] = datetime.now().isoformat()
                else:
                    # Add new port
                    new_port = port.copy()
                    new_port["source"] = port.get("source", scan_type)
                    new_port["last_verified"] = datetime.now().isoformat()
                    merged_ports[port_num] = new_port
        
        return list(merged_ports.values())
    
    def migrate_legacy_data(self, legacy_device: Dict[str, Any]) -> Dict[str, Any]:
        """Migrate from legacy format to unified format"""
        unified_device = self.create_unified_device(
            legacy_device.get("ip", ""),
            legacy_device.get("mac", "")
        )
        
        # Copy core information
        basic_fields = ["hostname", "vendor", "device_type", "status", "last_seen", "alias", "notes"]
        for field in basic_fields:
            if field in legacy_device:
                unified_device[field] = legacy_device[field]
        
        # Convert ports
        if "open_ports" in legacy_device:
            unified_ports = []
            for port in legacy_device["open_ports"]:
                unified_port = self.create_unified_port(
                    port.get("port", 0),
                    service=port.get("service", port.get("description", "unknown")),
                    state=port.get("state", "open"),
                    version=port.get("version", ""),
                    product=port.get("product", ""),
                    description=port.get("description", ""),
                    manual=port.get("manual", False),
                    source=port.get("source", "legacy")
                )
                unified_ports.append(unified_port)
            unified_device["open_ports"] = unified_ports
        
        # Migrate legacy analysis data
        analysis_data = {
            "last_normal_scan": None,
            "last_enhanced_analysis": None,
            "normal_scan_info": {},
            "enhanced_analysis_info": {}
        }
        
        # Migrate enhanced info
        if "enhanced_info" in legacy_device and legacy_device["enhanced_info"]:
            analysis_data["normal_scan_info"] = legacy_device["enhanced_info"]
            analysis_data["last_normal_scan"] = legacy_device.get("last_seen")
        
        # Migrate enhanced comprehensive info
        if "enhanced_comprehensive_info" in legacy_device and legacy_device["enhanced_comprehensive_info"]:
            analysis_data["enhanced_analysis_info"] = legacy_device["enhanced_comprehensive_info"]
            analysis_data["last_enhanced_analysis"] = legacy_device.get("last_enhanced_analysis")
        
        # Migrate advanced scan summary
        if "advanced_scan_summary" in legacy_device and legacy_device["advanced_scan_summary"]:
            if not analysis_data["enhanced_analysis_info"]:
                analysis_data["enhanced_analysis_info"] = legacy_device["advanced_scan_summary"]
        
        unified_device["analysis_data"] = analysis_data
        
        # For backward compatibility, preserve legacy fields
        unified_device["enhanced_info"] = legacy_device.get("enhanced_info")
        unified_device["enhanced_comprehensive_info"] = legacy_device.get("enhanced_comprehensive_info")
        unified_device["advanced_scan_summary"] = legacy_device.get("advanced_scan_summary")
        unified_device["last_enhanced_analysis"] = legacy_device.get("last_enhanced_analysis")
        
        return unified_device
    
    def validate_device_schema(self, device: Dict[str, Any]) -> bool:
        """Validate device schema"""
        required_fields = ["ip", "mac", "hostname", "vendor", "device_type", "open_ports", "analysis_data"]
        
        for field in required_fields:
            if field not in device:
                return False
        
        # Check analysis data structure
        if "analysis_data" in device:
            analysis_data = device["analysis_data"]
            required_analysis_fields = ["last_normal_scan", "last_enhanced_analysis", 
                                      "normal_scan_info", "enhanced_analysis_info"]
            for field in required_analysis_fields:
                if field not in analysis_data:
                    return False
        
        return True
    
    def get_device_summary(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """Return device summary information"""
        summary = {
            "ip": device.get("ip"),
            "alias": device.get("alias", ""),
            "device_type": device.get("device_type", ""),
            "port_count": len(device.get("open_ports", [])),
            "last_seen": device.get("last_seen"),
            "status": device.get("status", "offline"),
            "has_normal_scan": False,
            "has_enhanced_analysis": False
        }
        
        if "analysis_data" in device:
            analysis_data = device["analysis_data"]
            summary["has_normal_scan"] = bool(analysis_data.get("last_normal_scan"))
            summary["has_enhanced_analysis"] = bool(analysis_data.get("last_enhanced_analysis"))
            summary["last_normal_scan"] = analysis_data.get("last_normal_scan")
            summary["last_enhanced_analysis"] = analysis_data.get("last_enhanced_analysis")
        
        return summary

# Global instance
unified_model = UnifiedDeviceModel()