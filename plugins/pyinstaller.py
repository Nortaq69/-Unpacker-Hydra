"""
PyInstaller Plugin
Advanced extraction and analysis for PyInstaller executables.
"""

import os
import struct
import zlib
import marshal
from pathlib import Path
from typing import Dict, List, Optional, Any
import tempfile
import subprocess

class PyInstallerPlugin:
    """Advanced PyInstaller extraction plugin."""
    
    def __init__(self):
        self.name = "PyInstaller"
        self.version = "1.0.0"
        self.description = "Advanced PyInstaller extraction and analysis"
        
    def can_handle(self, target_path: Path) -> bool:
        """Check if this plugin can handle the target."""
        try:
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Look for PyInstaller signatures
            signatures = [
                b'PYZ-00.pyz',
                b'PYZ-01.pyz',
                b'pyiboot',
                b'pyimod',
                b'PyInstaller'
            ]
            
            for sig in signatures:
                if sig in data:
                    return True
                    
            return False
            
        except Exception:
            return False
            
    def extract(self, target_path: Path, output_dir: Path, options: Dict[str, Any]) -> Dict[str, Any]:
        """Extract PyInstaller executable."""
        try:
            # Create output structure
            (output_dir / 'pyinstaller').mkdir(exist_ok=True)
            (output_dir / 'pyinstaller' / 'archive').mkdir(exist_ok=True)
            (output_dir / 'pyinstaller' / 'extracted').mkdir(exist_ok=True)
            
            # Read the executable
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Find PyInstaller archive
            archive_info = self._find_archive(data)
            if not archive_info:
                return {'success': False, 'error': 'PyInstaller archive not found'}
                
            # Extract archive
            extracted_files = self._extract_archive(data, archive_info, output_dir)
            
            # Analyze extracted files
            analysis = self._analyze_extracted_files(extracted_files)
            
            return {
                'success': True,
                'extracted_files': extracted_files,
                'analysis': analysis,
                'archive_info': archive_info
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _find_archive(self, data: bytes) -> Optional[Dict[str, Any]]:
        """Find PyInstaller archive in executable."""
        # Look for PYZ magic
        pyz_positions = []
        
        # Find all PYZ occurrences
        pos = 0
        while True:
            pos = data.find(b'PYZ-', pos)
            if pos == -1:
                break
            pyz_positions.append(pos)
            pos += 1
            
        if not pyz_positions:
            return None
            
        # Analyze each PYZ section
        for pos in pyz_positions:
            try:
                # Try to parse as PYZ archive
                archive_info = self._parse_pyz_archive(data, pos)
                if archive_info:
                    return archive_info
            except Exception:
                continue
                
        return None
        
    def _parse_pyz_archive(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Parse PYZ archive header."""
        try:
            # Read PYZ header
            if offset + 16 > len(data):
                return None
                
            # Check for PYZ magic
            magic = data[offset:offset+8]
            if not magic.startswith(b'PYZ-'):
                return None
                
            # Read archive info
            archive_info = {
                'offset': offset,
                'magic': magic.decode('ascii'),
                'version': data[offset+8:offset+12],
                'files': []
            }
            
            # Try to find file entries
            current_pos = offset + 12
            while current_pos < len(data) - 8:
                try:
                    # Look for file entry pattern
                    file_entry = self._parse_file_entry(data, current_pos)
                    if file_entry:
                        archive_info['files'].append(file_entry)
                        current_pos = file_entry['next_offset']
                    else:
                        current_pos += 1
                except Exception:
                    current_pos += 1
                    
            return archive_info if archive_info['files'] else None
            
        except Exception:
            return None
            
    def _parse_file_entry(self, data: bytes, offset: int) -> Optional[Dict[str, Any]]:
        """Parse a file entry in the PYZ archive."""
        try:
            # This is a simplified parser - real PyInstaller archives are more complex
            # Look for patterns that indicate file boundaries
            
            # Check for reasonable file size
            if offset + 20 > len(data):
                return None
                
            # Try to find file name
            name_start = offset
            name_end = data.find(b'\x00', name_start)
            if name_end == -1 or name_end - name_start > 256:
                return None
                
            filename = data[name_start:name_end].decode('utf-8', errors='ignore')
            
            # Skip null terminator
            data_start = name_end + 1
            
            # Look for data end (simplified)
            data_end = data.find(b'\x00\x00\x00', data_start)
            if data_end == -1:
                data_end = min(data_start + 1024*1024, len(data))  # Max 1MB per file
                
            return {
                'name': filename,
                'offset': data_start,
                'size': data_end - data_start,
                'next_offset': data_end + 3
            }
            
        except Exception:
            return None
            
    def _extract_archive(self, data: bytes, archive_info: Dict[str, Any], output_dir: Path) -> List[Path]:
        """Extract files from PyInstaller archive."""
        extracted_files = []
        
        try:
            archive_dir = output_dir / 'pyinstaller' / 'extracted'
            
            for file_entry in archive_info['files']:
                try:
                    # Extract file data
                    file_data = data[file_entry['offset']:file_entry['offset'] + file_entry['size']]
                    
                    # Create file path
                    file_path = archive_dir / file_entry['name']
                    file_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    # Write file
                    with open(file_path, 'wb') as f:
                        f.write(file_data)
                        
                    extracted_files.append(file_path)
                    
                except Exception as e:
                    print(f"Error extracting {file_entry['name']}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error extracting archive: {e}")
            
        return extracted_files
        
    def _analyze_extracted_files(self, extracted_files: List[Path]) -> Dict[str, Any]:
        """Analyze extracted files."""
        analysis = {
            'total_files': len(extracted_files),
            'file_types': {},
            'python_files': [],
            'resource_files': [],
            'suspicious_files': []
        }
        
        for file_path in extracted_files:
            try:
                # Analyze file type
                extension = file_path.suffix.lower()
                analysis['file_types'][extension] = analysis['file_types'].get(extension, 0) + 1
                
                # Check for Python files
                if extension in ['.py', '.pyc', '.pyo']:
                    analysis['python_files'].append(str(file_path))
                    
                # Check for resource files
                if extension in ['.png', '.jpg', '.jpeg', '.gif', '.ico', '.bmp']:
                    analysis['resource_files'].append(str(file_path))
                    
                # Check for suspicious files
                suspicious_extensions = ['.dll', '.exe', '.bat', '.cmd', '.vbs']
                if extension in suspicious_extensions:
                    analysis['suspicious_files'].append(str(file_path))
                    
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
                
        return analysis
        
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': 'Unpacker Hydra Team',
            'capabilities': [
                'PyInstaller archive detection',
                'PYZ archive extraction',
                'File analysis',
                'Python bytecode extraction'
            ]
        }
        
    def get_help(self) -> str:
        """Get help information for this plugin."""
        return """
PyInstaller Plugin Help:

This plugin provides advanced extraction capabilities for PyInstaller executables.

Features:
- Automatic PyInstaller detection
- PYZ archive extraction
- File type analysis
- Python bytecode extraction

Usage:
The plugin automatically activates when a PyInstaller executable is detected.

Output:
- Extracted files in pyinstaller/extracted/
- Analysis report with file statistics
- Python bytecode files for further analysis

Note: This plugin works best with standard PyInstaller executables.
Modified or obfuscated PyInstaller executables may require additional analysis.
""" 