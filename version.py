#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dynamic version management for My Network Scanner
"""

import subprocess
import os
from datetime import datetime

# Fallback version if git is not available
FALLBACK_VERSION = "1.0.4"

def is_docker_environment():
    """Check if running in Docker container"""
    try:
        with open('/proc/1/cgroup', 'r') as f:
            return 'docker' in f.read() or 'containerd' in f.read()
    except:
        return False

def get_git_version():
    """Get version info from git tags"""
    try:
        # Check git tags
        result = subprocess.run(
            ['git', 'describe', '--tags', '--abbrev=0'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            tag = result.stdout.strip()
            # Remove v prefix
            if tag.startswith('v'):
                tag = tag[1:]
            return tag
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def get_git_commit_count():
    """Get git commit count"""
    try:
        result = subprocess.run(
            ['git', 'rev-list', '--count', 'HEAD'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return int(result.stdout.strip())
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError, ValueError):
        pass
    
    return None

def get_git_commit_hash():
    """Get git commit hash (short form)"""
    try:
        result = subprocess.run(
            ['git', 'rev-parse', '--short', 'HEAD'], 
            capture_output=True, 
            text=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def is_git_dirty():
    """Check if there are changes in the git working directory"""
    try:
        result = subprocess.run(
            ['git', 'diff-index', '--quiet', 'HEAD', '--'], 
            capture_output=True, 
            cwd=os.path.dirname(__file__),
            timeout=5
        )
        
        # Return code 0 means clean, 1 means dirty
        return result.returncode != 0
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return False

def get_docker_image_version():
    """Get version info from Docker image"""
    try:
        # Get version from Docker image label
        result = subprocess.run([
            'docker', 'inspect', '--format', '{{index .Config.Labels "version"}}', 
            'fxerkan/my-network-scanner:latest'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
        # Alternatively, try built-in label
        result = subprocess.run([
            'docker', 'inspect', '--format', '{{index .Config.Labels "org.opencontainers.image.version"}}', 
            'fxerkan/my-network-scanner:latest'
        ], capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
            
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    return None

def get_version():
    """Main version function - returns dynamic version"""
    # If running in Docker and git is not available
    if is_docker_environment():
        # Try to get version from Docker image first
        docker_version = get_docker_image_version()
        if docker_version:
            return docker_version
            
        # If git is not available, use fallback
        if not os.path.exists('.git'):
            return FALLBACK_VERSION
    
    git_version = get_git_version()
    
    if git_version:
        # If git tag exists, use it
        version = git_version
        
        # If not in Docker or git is not dirty, add commit hash
        if not is_docker_environment():
            commit_hash = get_git_commit_hash()
            if commit_hash:
                version += f"-{commit_hash}"
                
            # If working directory is dirty, add +
            if is_git_dirty():
                version += "+"
            
        return version
    else:
        # If no git tag, create minor version based on commit count
        commit_count = get_git_commit_count()
        
        if commit_count is not None:
            # Automatically create version based on commit count
            major = 1
            minor = 0
            patch = min(commit_count, 999)  # Limit to max 999
            
            version = f"{major}.{minor}.{patch}"
            
            # If not in Docker, add commit hash
            if not is_docker_environment():
                commit_hash = get_git_commit_hash()
                if commit_hash:
                    version += f"-{commit_hash}"
                    
                if is_git_dirty():
                    version += "+"
                
            return version
        else:
            # If git is not available at all, use fallback
            return FALLBACK_VERSION

def get_version_info():
    """Return detailed version information"""
    version = get_version()
    commit_hash = get_git_commit_hash()
    commit_count = get_git_commit_count()
    is_dirty = is_git_dirty()
    
    return {
        "version": version,
        "commit_hash": commit_hash,
        "commit_count": commit_count,
        "is_dirty": is_dirty,
        "build_time": datetime.now().isoformat(),
        "git_available": commit_hash is not None
    }

# Module-level version
__version__ = get_version()

if __name__ == "__main__":
    # Test the version system
    print(f"Version: {get_version()}")
    info = get_version_info()
    print(f"Full info: {info}")