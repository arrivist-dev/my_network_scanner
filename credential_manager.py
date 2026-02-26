#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure Credential Manager
Stores sensitive information such as SSH, FTP, API, etc. in encrypted form
"""

import os
import json
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import getpass
from datetime import datetime

class CredentialManager:
    def __init__(self, config_dir='config'):
        self.config_dir = config_dir
        # Now using lan_devices.json
        self.devices_file = os.path.join('data', 'lan_devices.json')
        self.salt_file = os.path.join(config_dir, '.salt')
        self.key_file = os.path.join(config_dir, '.key_info')
        self.config_file = os.path.join(config_dir, 'config.json')
        
        # Check multiple sources for master password
        self.master_password = self._get_master_password_from_sources()
        
        # Initialize encryption key
        self.fernet = None
        self._initialize_encryption()
        
        # Create data directory
        os.makedirs('data', exist_ok=True)
    
    def _initialize_encryption(self):
        """Initializes the encryption system"""
        try:
            # Create config directory
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Check if salt file exists
            if not os.path.exists(self.salt_file):
                # First run, create new salt
                print(f"📁 Creating new salt file: {self.salt_file}")
                self._create_new_salt()
            
            # Load salt
            with open(self.salt_file, 'rb') as f:
                salt = f.read()
            
            # Get master password
            if not self.master_password:
                print("🔐 Getting master password...")
                self.master_password = self._get_master_password()
            else:
                print("✅ Master password loaded from config")
            
            # Derive key
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.master_password.encode()))
            self.fernet = Fernet(key)
            
            # Update key info file
            self._update_key_info()
            
            print("✅ Encryption initialized successfully")
            
        except Exception as e:
            print(f"❌ Encryption initialization error: {e}")
            raise
    
    def _create_new_salt(self):
        """Creates a new salt"""
        salt = secrets.token_bytes(16)
        with open(self.salt_file, 'wb') as f:
            f.write(salt)
        
        # Hide salt file (on Unix systems)
        if os.name == 'posix':
            os.chmod(self.salt_file, 0o600)
    
    def _update_key_info(self):
        """Updates key information"""
        key_info = {
            'created_at': datetime.now().isoformat(),
            'algorithm': 'PBKDF2HMAC-SHA256',
            'iterations': 100000,
            'salt_length': 16
        }
        
        with open(self.key_file, 'w') as f:
            json.dump(key_info, f, indent=2)
        
        # Hide key info file
        if os.name == 'posix':
            os.chmod(self.key_file, 0o600)
    
    def _get_master_password_from_sources(self):
        """Gets the master password from different sources"""
        # 1. Check environment variable
        env_password = os.environ.get('LAN_SCANNER_PASSWORD')
        if env_password:
            return env_password
        
        # 2. Check config.json
        config_password = self._get_password_from_config()
        if config_password:
            return config_password
        
        # 3. If none, ask user
        return None
    
    def _get_password_from_config(self):
        """Reads master password from config.json"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                security_settings = config.get('security_settings', {})
                return security_settings.get('master_password')
        except Exception as e:
            print(f"Error reading password from config file: {e}")
        return None
    
    def _get_master_password(self):
        """Gets the master password from the user"""
        # Check if first run - if salt file exists, it's already set up
        if not os.path.exists(self.salt_file):
            print("🔐 LAN Scanner Credential Manager")
            print("First time setup. Please set a master password.")
            print("This password will protect all your device access information.")
            print("Tip: You can store the password in config.json as 'security_settings.master_password'.")
            
            while True:
                password1 = getpass.getpass("Master Password: ")
                password2 = getpass.getpass("Master Password (repeat): ")
                
                if password1 == password2:
                    if len(password1) < 8:
                        print("❌ Password must be at least 8 characters!")
                        continue
                    
                    # Offer to save to config.json
                    save_to_config = input("\nWould you like to save this password to config.json? (y/n): ").lower() == 'y'
                    if save_to_config:
                        self._save_password_to_config(password1)
                        print("✅ Password saved to config.json.")
                    
                    return password1
                else:
                    print("❌ Passwords do not match!")
        else:
            # Existing file, ask for password
            return getpass.getpass("Master Password: ")
    
    def _save_password_to_config(self, password):
        """Saves the master password to config.json"""
        try:
            config = {}
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
            
            if 'security_settings' not in config:
                config['security_settings'] = {}
            
            config['security_settings']['master_password'] = password
            
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            print(f"Error saving password to config: {e}")
    
    def save_device_credentials(self, ip, access_type, username=None, password=None, port=None, additional_info=None):
        """Saves device credentials to lan_devices.json in encrypted form"""
        try:
            # Load lan_devices.json
            devices = self._load_devices()
            
            # Find IP
            device_index = None
            for i, d in enumerate(devices):
                if d.get('ip') == ip:
                    device_index = i
                    break
            
            if device_index is None:
                print(f"⚠️ Device not found: {ip}")
                return False
            
            # Create encrypted credentials field
            if 'encrypted_credentials' not in devices[device_index]:
                devices[device_index]['encrypted_credentials'] = {}
            elif isinstance(devices[device_index]['encrypted_credentials'], str):
                # Convert from old format to new format
                devices[device_index]['encrypted_credentials'] = {}
            
            # Prepare credential data
            credential_data = {
                'username': username,
                'password': password,
                'port': port,
                'additional_info': additional_info or {},
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            }
            
            # Encrypt and base64 encode
            json_data = json.dumps(credential_data)
            encrypted_data = self.fernet.encrypt(json_data.encode()).decode()
            devices[device_index]['encrypted_credentials'][access_type] = encrypted_data
            
            # Save to file
            self._save_devices(devices)
            
            print(f"✅ Credential saved: {ip} -> {access_type} ({username})")
            return True
            
        except Exception as e:
            print(f"❌ Error saving credential: {e}")
            return False
    
    def get_device_credentials(self, ip, access_type=None):
        """Loads and decrypts device credentials from lan_devices.json"""
        try:
            devices = self._load_devices()
            
            # Find IP
            device = None
            for d in devices:
                if d.get('ip') == ip:
                    device = d
                    break
            
            if not device or 'encrypted_credentials' not in device:
                return None
            
            encrypted_creds = device['encrypted_credentials']
            
            # Check and fix old string format
            if isinstance(encrypted_creds, str):
                print(f"⚠️ {ip} - Old credential format detected, cleaning up...")
                self._remove_corrupted_credential(ip, None)
                return None
            
            # Error if not dict
            if not isinstance(encrypted_creds, dict):
                print(f"⚠️ {ip} - Unexpected credential format: {type(encrypted_creds)}")
                return None
            
            if access_type:
                # Request specific access type
                if access_type in encrypted_creds:
                    encrypted_data = encrypted_creds[access_type]
                    
                    # If string, decrypt
                    if isinstance(encrypted_data, str):
                        try:
                            decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                            return json.loads(decrypted_data)
                        except Exception as decrypt_error:
                            print(f"❌ {ip} {access_type} decrypt error: {decrypt_error}")
                            print(f"⚠️ Corrupted encrypted data, cleaning up...")
                            # Delete corrupted credential
                            self._remove_corrupted_credential(ip, access_type)
                            return None
                    else:
                        print(f"⚠️ {ip} {access_type} - Unexpected data type: {type(encrypted_data)}")
                        self._remove_corrupted_credential(ip, access_type)
                        return None
                    
                return None
            else:
                # Decrypt all credentials
                result = {}
                corrupted_keys = []
                
                for acc_type, encrypted_data in encrypted_creds.items():
                    try:
                        # If string, decrypt
                        if isinstance(encrypted_data, str):
                            try:
                                decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                                credential_obj = json.loads(decrypted_data)
                                result[acc_type] = credential_obj
                                result[acc_type]['has_password'] = bool(credential_obj.get('password'))
                            except Exception as decrypt_error:
                                print(f"❌ {ip} {acc_type} decrypt error: {decrypt_error}")
                                print(f"⚠️ Corrupted encrypted data, cleaning up...")
                                corrupted_keys.append(acc_type)
                                continue
                        else:
                            print(f"⚠️ {ip} {acc_type} - Unexpected data type: {type(encrypted_data)}")
                            corrupted_keys.append(acc_type)
                            continue
                    except Exception as e:
                        print(f"⚠️ {ip} {acc_type} general error: {e}")
                        corrupted_keys.append(acc_type)
                        continue
                
                # Clean up corrupted credentials
                for key in corrupted_keys:
                    self._remove_corrupted_credential(ip, key)
                
                return result
            
        except Exception as e:
            print(f"❌ Error loading credential: {e}")
            return None
    
    def _load_devices(self):
        """Loads lan_devices.json file"""
        try:
            if os.path.exists(self.devices_file):
                with open(self.devices_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            return []
        except Exception as e:
            print(f"❌ Error loading devices file: {e}")
            return []
    
    def _save_devices(self, devices):
        """Saves lan_devices.json file"""
        try:
            with open(self.devices_file, 'w', encoding='utf-8') as f:
                json.dump(devices, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"❌ Error saving devices file: {e}")
            return False
            return None
    
    def get_all_credentials(self):
        """Returns all credentials"""
        try:
            return self._load_credentials()
        except Exception as e:
            print(f"❌ Error loading all credentials: {e}")
            return {}
    
    def delete_device_credentials(self, ip, access_type=None):
        """Deletes device credentials"""
        try:
            credentials = self._load_credentials()
            
            if ip in credentials:
                if access_type:
                    if access_type in credentials[ip]:
                        del credentials[ip][access_type]
                        print(f"✅ Credential deleted: {ip} -> {access_type}")
                else:
                    del credentials[ip]
                    print(f"✅ All credentials deleted: {ip}")
                
                self._save_credentials(credentials)
                return True
            
            return False
            
        except Exception as e:
            print(f"❌ Error deleting credential: {e}")
            return False
    
    def _load_credentials(self):
        """OLD METHOD - No longer used, now using lan_devices.json"""
        if not os.path.exists(self.credentials_file):
            print(f"📝 Credential file not found, will be created: {self.credentials_file}")
            return {}
        
        try:
            with open(self.credentials_file, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data:
                print("⚠️ Credential file is empty")
                return {}
            
            # Decrypt
            decrypted_data = self.fernet.decrypt(encrypted_data)
            credentials = json.loads(decrypted_data.decode())
            
            print(f"✅ Credential file loaded successfully: {len(credentials)} devices")
            return credentials
            
        except Exception as e:
            print(f"❌ Error loading credential file: {e}")
            print(f"❌ File size: {os.path.getsize(self.credentials_file) if os.path.exists(self.credentials_file) else 'N/A'} bytes")
            
            # If corrupted file, create backup
            if os.path.exists(self.credentials_file):
                backup_file = f"{self.credentials_file}.backup.{int(datetime.now().timestamp())}"
                try:
                    os.rename(self.credentials_file, backup_file)
                    print(f"⚠️ Corrupted credential file backed up: {backup_file}")
                except Exception as backup_error:
                    print(f"❌ Error creating backup: {backup_error}")
                    # If backup fails, delete file
                    try:
                        os.remove(self.credentials_file)
                        print("🗑️ Corrupted file deleted")
                    except Exception as delete_error:
                        print(f"❌ Error deleting file: {delete_error}")
            
            return {}
    
    def _save_credentials(self, credentials):
        """Saves credentials in encrypted form"""
        try:
            if not self.fernet:
                print("❌ No Fernet instance, initializing encryption...")
                self._initialize_encryption()
            
            # Serialize as JSON
            json_data = json.dumps(credentials, indent=2, ensure_ascii=False)
            
            # Encrypt
            encrypted_data = self.fernet.encrypt(json_data.encode('utf-8'))
            
            # Write to file
            os.makedirs(self.config_dir, exist_ok=True)
            
            # Write to temp file first, then rename (atomic operation)
            temp_file = self.credentials_file + '.tmp'
            with open(temp_file, 'wb') as f:
                f.write(encrypted_data)
            
            # Atomic rename
            os.rename(temp_file, self.credentials_file)
            
            # Tighten file permissions
            if os.name == 'posix':
                os.chmod(self.credentials_file, 0o600)
            
            print(f"✅ Credential file saved: {len(credentials)} devices, {len(encrypted_data)} bytes")
            
        except Exception as e:
            print(f"❌ Error saving credential file: {e}")
            # Clean up temp file
            temp_file = self.credentials_file + '.tmp'
            if os.path.exists(temp_file):
                try:
                    os.remove(temp_file)
                except:
                    pass
            raise
    
    def test_credentials(self, ip, access_type):
        """Tests if credentials work correctly"""
        try:
            creds = self.get_device_credentials(ip, access_type)
            if not creds:
                return {'success': False, 'error': 'Credential not found'}
            
            return self._test_credentials_direct(ip, access_type, creds)
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_credentials_direct(self, ip, access_type, creds):
        """Directly tests the given credentials"""
        try:
            if access_type == 'ssh':
                return self._test_ssh_credentials(ip, creds)
            elif access_type == 'ftp':
                return self._test_ftp_credentials(ip, creds)
            elif access_type == 'http':
                return self._test_http_credentials(ip, creds)
            elif access_type == 'telnet':
                return self._test_telnet_credentials(ip, creds)
            elif access_type == 'snmp':
                return self._test_snmp_credentials(ip, creds)
            elif access_type == 'api':
                return self._test_api_credentials(ip, creds)
            else:
                return {'success': False, 'error': f'Unsupported access type: {access_type}'}
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _test_ssh_credentials(self, ip, creds):
        """Tests SSH credentials"""
        try:
            import paramiko
            import socket
            
            # First check basic connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                port = int(creds.get('port', 22))
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result != 0:
                    return {
                        'success': False,
                        'error': f'Port {port} is closed or unreachable'
                    }
            except socket.error as e:
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Network connection error: Cannot reach {ip} (routing issue)'
                    }
                elif "Connection refused" in error_msg:
                    return {
                        'success': False,
                        'error': f'Connection refused: {ip}:{port} SSH service may not be running'
                    }
                elif "Network is unreachable" in error_msg:
                    return {
                        'success': False,
                        'error': f'Network unreachable: Is {ip} on the local network? Is VPN connected?'
                    }
                elif "Host is down" in error_msg:
                    return {
                        'success': False,
                        'error': f'Target device is down: {ip} is offline'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Network error: {error_msg}'
                    }
            
            # If connectivity is OK, try SSH
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            ssh.connect(
                ip, 
                username=creds.get('username'),
                password=creds.get('password'),
                port=creds.get('port', 22),
                timeout=10
            )
            
            # Simple command test
            stdin, stdout, stderr = ssh.exec_command('whoami')
            user = stdout.read().decode().strip()
            
            ssh.close()
            
            return {
                'success': True,
                'user': user,
                'message': 'SSH connection successful'
            }
            
        except paramiko.AuthenticationException:
            return {
                'success': False,
                'error': 'SSH authentication error: Invalid username/password'
            }
        except paramiko.SSHException as e:
            error_msg = str(e)
            if "Unable to connect" in error_msg:
                return {
                    'success': False,
                    'error': f'Unable to establish SSH connection: {error_msg}'
                }
            else:
                return {
                    'success': False,
                    'error': f'SSH protocol error: {error_msg}'
                }
        except socket.error as e:
            error_msg = str(e)
            if "Can't assign requested address" in error_msg:
                return {
                    'success': False,
                    'error': f'Network connection error: Cannot reach {ip} (invalid IP address)'
                }
            else:
                return {
                    'success': False,
                    'error': f'Network error: {error_msg}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'SSH test error: {str(e)}'
            }
    
    def _test_ftp_credentials(self, ip, creds):
        """Tests FTP credentials"""
        try:
            import ftplib
            import socket
            
            # First check basic connectivity
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                port = int(creds.get('port', 21))
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result != 0:
                    return {
                        'success': False,
                        'error': f'FTP port {port} is closed or unreachable'
                    }
            except socket.error as e:
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Network connection error: Cannot reach {ip}'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Network error: {error_msg}'
                    }
            
            ftp = ftplib.FTP()
            ftp.connect(ip, int(creds.get('port', 21)))
            ftp.login(creds.get('username'), creds.get('password'))
            
            # Simple directory listing test
            ftp.nlst()
            ftp.quit()
            
            return {
                'success': True,
                'message': 'FTP connection successful'
            }
            
        except ftplib.error_perm as e:
            return {
                'success': False,
                'error': f'FTP authentication error: {str(e)}'
            }
        except ftplib.error_temp as e:
            return {
                'success': False,
                'error': f'FTP temporary error: {str(e)}'
            }
        except socket.error as e:
            error_msg = str(e)
            if "Can't assign requested address" in error_msg:
                return {
                    'success': False,
                    'error': f'Network connection error: Cannot reach {ip}'
                }
            else:
                return {
                    'success': False,
                    'error': f'Network error: {error_msg}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': f'FTP test error: {str(e)}'
            }
    
    def _test_http_credentials(self, ip, creds):
        """Tests HTTP Basic Auth credentials"""
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            
            port = creds.get('port', 80)
            username = creds.get('username')
            password = creds.get('password')
            
            # Try both HTTP and HTTPS
            protocols = ['http', 'https'] if port in [80, 443, 8080, 8443] else ['http']
            
            for protocol in protocols:
                try:
                    url = f"{protocol}://{ip}:{port}/"
                    
                    # First try without credentials
                    response = requests.get(url, timeout=10, verify=False)
                    
                    if response.status_code == 401:  # Unauthorized - auth required
                        # Try again with credentials
                        auth_response = requests.get(
                            url, 
                            auth=HTTPBasicAuth(username, password),
                            timeout=10,
                            verify=False
                        )
                        
                        if auth_response.status_code == 200:
                            return {
                                'success': True,
                                'message': f'HTTP Basic Auth successful ({protocol.upper()})',
                                'details': f'Status: {auth_response.status_code}'
                            }
                        else:
                            return {
                                'success': False,
                                'error': f'HTTP Auth failed: Status {auth_response.status_code}'
                            }
                    
                    elif response.status_code == 200:
                        return {
                            'success': True,
                            'message': f'HTTP connection successful (no auth required)',
                            'details': f'Status: {response.status_code}'
                        }
                    
                except requests.exceptions.RequestException:
                    continue
            
            return {
                'success': False,
                'error': 'HTTP service unreachable'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'HTTP test error: {str(e)}'
            }
    
    def _test_telnet_credentials(self, ip, creds):
        """Tests Telnet credentials - Socket based implementation"""
        try:
            import socket
            
            port = int(creds.get('port', 23))
            username = creds.get('username')
            password = creds.get('password')
            
            # Telnet connection with socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            
            try:
                sock.connect((ip, port))
                
                # Simple connection test
                response = sock.recv(1024).decode('ascii', errors='ignore')
                
                if response:  # Any response means connection is successful
                    sock.close()
                    return {
                        'success': True,
                        'message': 'Telnet port is open and responding',
                        'details': f'Response: {response[:50]}...'
                    }
                else:
                    sock.close()
                    return {
                        'success': True,
                        'message': 'Telnet port is open (no response)'
                    }
                    
            except socket.error as e:
                sock.close()
                error_msg = str(e)
                if "Can't assign requested address" in error_msg:
                    return {
                        'success': False,
                        'error': f'Network connection error: Cannot reach {ip}'
                    }
                elif "Connection refused" in error_msg:
                    return {
                        'success': False,
                        'error': f'Telnet service is down: {ip}:{port}'
                    }
                elif "Network is unreachable" in error_msg:
                    return {
                        'success': False,
                        'error': f'Network unreachable: Is {ip} on the local network?'
                    }
                else:
                    return {
                        'success': False,
                        'error': f'Telnet connection error: {error_msg}'
                    }
            except Exception as e:
                sock.close()
                return {
                    'success': False,
                    'error': f'Telnet connection error: {str(e)}'
                }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Telnet test error: {str(e)}'
            }
    
    def _test_snmp_credentials(self, ip, creds):
        """Tests SNMP community string"""
        try:
            # pysnmp is required for SNMP test
            try:
                from pysnmp.hlapi import (
                    SnmpEngine, CommunityData, UdpTransportTarget, ContextData,
                    ObjectType, ObjectIdentity, nextCmd
                )
            except ImportError:
                return {
                    'success': False,
                    'error': 'pysnmp library is required for SNMP test'
                }
            
            port = creds.get('port', 161)
            community = creds.get('username', 'public')  # In SNMP, username = community string
            
            # Try to query System OID
            for (errorIndication, errorStatus, errorIndex, varBinds) in nextCmd(
                SnmpEngine(),
                CommunityData(community),
                UdpTransportTarget((ip, port), timeout=10),
                ContextData(),
                ObjectType(ObjectIdentity('1.3.6.1.2.1.1.1.0')),  # sysDescr
                lexicographicMode=False,
                maxRows=1
            ):
                if errorIndication:
                    return {
                        'success': False,
                        'error': f'SNMP error: {errorIndication}'
                    }
                elif errorStatus:
                    return {
                        'success': False,
                        'error': f'SNMP error: {errorStatus.prettyPrint()}'
                    }
                else:
                    # Successful response
                    for varBind in varBinds:
                        value = varBind[1].prettyPrint()
                        return {
                            'success': True,
                            'message': 'SNMP community string is valid',
                            'details': f'System: {value[:50]}...'
                        }
            
            return {
                'success': False,
                'error': 'No SNMP response received'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'SNMP test error: {str(e)}'
            }
    
    def _test_api_credentials(self, ip, creds):
        """Tests API Token"""
        try:
            import requests
            
            port = creds.get('port', 80)
            token = creds.get('password')  # API token in password field
            additional_info = creds.get('additional_info', {})
            
            # Use endpoint from additional info if available
            endpoints = []
            if isinstance(additional_info, dict):
                if 'endpoint' in additional_info:
                    endpoints.append(additional_info['endpoint'])
                if 'endpoints' in additional_info:
                    endpoints.extend(additional_info['endpoints'])
            
            # Default API endpoints
            if not endpoints:
                endpoints = ['/api', '/api/v1', '/api/status', '/status', '/']
            
            protocols = ['http', 'https'] if port in [443, 8443] else ['http']
            
            for protocol in protocols:
                for endpoint in endpoints:
                    try:
                        url = f"{protocol}://{ip}:{port}{endpoint}"
                        
                        # Try different auth methods
                        auth_methods = [
                            {'headers': {'Authorization': f'Bearer {token}'}},
                            {'headers': {'X-API-Key': token}},
                            {'headers': {'API-Key': token}},
                            {'params': {'token': token}},
                            {'params': {'api_key': token}}
                        ]
                        
                        for auth_method in auth_methods:
                            response = requests.get(
                                url,
                                timeout=10,
                                verify=False,
                                **auth_method
                            )
                            
                            if response.status_code in [200, 201]:
                                return {
                                    'success': True,
                                    'message': f'API token is valid',
                                    'details': f'Endpoint: {endpoint}, Status: {response.status_code}'
                                }
                            
                    except requests.exceptions.RequestException:
                        continue
            
            return {
                'success': False,
                'error': 'API token is invalid or endpoint unreachable'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'API test error: {str(e)}'
            }
    
    def get_all_device_credentials(self, ip):
        """Returns all access types credentials for a device"""
        try:
            all_creds = {}
            access_types = ['ssh', 'ftp', 'http', 'telnet', 'snmp', 'api']
            
            for access_type in access_types:
                creds = self.get_device_credentials(ip, access_type)
                if creds:
                    all_creds[access_type] = creds
            
            return all_creds
            
        except Exception as e:
            print(f"Get all device credentials error: {e}")
            return {}
    
    def change_master_password(self):
        """Changes the master password"""
        try:
            print("🔐 Changing Master Password")
            
            # Load existing credentials (from lan_devices.json)
            devices = self._load_devices()
            
            # Get new password
            while True:
                new_password1 = getpass.getpass("New Master Password: ")
                new_password2 = getpass.getpass("New Master Password (repeat): ")
                
                if new_password1 == new_password2:
                    if len(new_password1) < 8:
                        print("❌ Password must be at least 8 characters!")
                        continue
                    break
                else:
                    print("❌ Passwords do not match!")
            
            # Create new salt
            self._create_new_salt()
            
            # Restart system with new key
            self.master_password = new_password1
            self._initialize_encryption()
            
            # Re-encrypt credentials with new key
            for device in devices:
                if 'encrypted_credentials' in device:
                    # Decrypt each credential with old key and encrypt with new key
                    temp_creds = {}
                    for access_type, encrypted_data in device['encrypted_credentials'].items():
                        try:
                            # Decrypt with old key
                            decrypted_data = self.fernet.decrypt(encrypted_data.encode()).decode()
                            temp_creds[access_type] = json.loads(decrypted_data)
                        except Exception as e:
                            print(f"⚠️ {device['ip']} {access_type} decrypt error: {e}")
                    
                    # Encrypt with new key
                    device['encrypted_credentials'] = {}
                    for access_type, cred_data in temp_creds.items():
                        json_data = json.dumps(cred_data)
                        encrypted_data = self.fernet.encrypt(json_data.encode()).decode()
                        device['encrypted_credentials'][access_type] = encrypted_data
            
            # Save updated devices
            self._save_devices(devices)
            
            print("✅ Master password changed successfully!")
            return True
            
        except Exception as e:
            print(f"❌ Error changing master password: {e}")
            return False
    
    def _remove_corrupted_credential(self, ip, access_type):
        """Removes corrupted credential"""
        try:
            devices = self._load_devices()
            
            # Find IP
            device_index = None
            for i, d in enumerate(devices):
                if d.get('ip') == ip:
                    device_index = i
                    break
            
            if device_index is not None and 'encrypted_credentials' in devices[device_index]:
                if access_type is None:
                    # Clear all credentials
                    devices[device_index]['encrypted_credentials'] = {}
                    self._save_devices(devices)
                    print(f"🗑️ All corrupted credentials cleared: {ip}")
                elif access_type in devices[device_index]['encrypted_credentials']:
                    # Clear specific access_type
                    del devices[device_index]['encrypted_credentials'][access_type]
                    self._save_devices(devices)
                    print(f"🗑️ Corrupted credential cleared: {ip} -> {access_type}")
                    
        except Exception as e:
            print(f"❌ Error clearing corrupted credential: {e}")
    
    def export_credentials(self, export_file, include_passwords=False):
        """Exports credentials"""
        try:
            credentials = self._load_credentials()
            
            if not include_passwords:
                # Hide passwords
                for ip in credentials:
                    for access_type in credentials[ip]:
                        if 'password' in credentials[ip][access_type]:
                            credentials[ip][access_type]['password'] = '***HIDDEN***'
            
            with open(export_file, 'w') as f:
                json.dump(credentials, f, indent=2)
            
            print(f"✅ Credentials exported: {export_file}")
            return True
            
        except Exception as e:
            print(f"❌ Export error: {e}")
            return False
    
    def get_statistics(self):
        """Returns credential statistics"""
        try:
            credentials = self._load_credentials()
            
            total_devices = len(credentials)
            total_credentials = sum(len(creds) for creds in credentials.values())
            
            access_types = {}
            for device_creds in credentials.values():
                for access_type in device_creds.keys():
                    access_types[access_type] = access_types.get(access_type, 0) + 1
            
            return {
                'total_devices': total_devices,
                'total_credentials': total_credentials,
                'access_types': access_types,
                'encrypted_file': os.path.exists(self.credentials_file),
                'file_size': os.path.getsize(self.credentials_file) if os.path.exists(self.credentials_file) else 0
            }
            
        except Exception as e:
            print(f"❌ Statistics error: {e}")
            return {}


# Singleton instance
credential_manager = None
_initialization_lock = False

def get_credential_manager():
    """Returns the global credential manager instance"""
    global credential_manager, _initialization_lock
    
    if credential_manager is None and not _initialization_lock:
        _initialization_lock = True
        try:
            print("🔧 Creating CredentialManager instance...")
            credential_manager = CredentialManager()
            print("✅ CredentialManager instance ready")
        except Exception as e:
            print(f"❌ Error creating CredentialManager: {e}")
            _initialization_lock = False
            raise
        finally:
            _initialization_lock = False
    elif _initialization_lock:
        print("⏳ CredentialManager is already being created, waiting...")
        import time
        while _initialization_lock:
            time.sleep(0.1)
    
    return credential_manager


if __name__ == "__main__":
    # Test code
    cm = CredentialManager()
    
    # Add test credential
    cm.save_device_credentials(
        '192.168.1.100', 
        'ssh', 
        username='demo_user', 
        password='demo_password', 
        port=22
    )
    
    # Read test credential
    creds = cm.get_device_credentials('192.168.1.100', 'ssh')
    print(f"Loaded credential: {creds}")
    
    # Show statistics
    stats = cm.get_statistics()
    print(f"Statistics: {stats}")