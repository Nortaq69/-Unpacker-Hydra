"""
Packer Detection Module
Detects various packers and protection mechanisms in executables.
"""

import pefile
import yara
import re
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import yaml
import lief

class PackerDetector:
    def __init__(self):
        self.signatures = self._load_signatures()
        self.yara_rules = self._load_yara_rules()
        
    def _load_signatures(self) -> Dict:
        """Load packer signatures from YAML configuration."""
        signatures = {
            'pyinstaller': {
                'strings': [
                    'PyInstaller',
                    'pyiboot',
                    'pyimod',
                    'PYZ-00.pyz',
                    'PYZ-01.pyz'
                ],
                'magic_bytes': [
                    b'PYZ-00.pyz',
                    b'PYZ-01.pyz'
                ],
                'confidence': 95
            },
            'pyarmor': {
                'strings': [
                    'pyarmor',
                    'PyArmor',
                    '_pytransform',
                    'pytransform.dll'
                ],
                'magic_bytes': [
                    b'pyarmor',
                    b'PyArmor'
                ],
                'confidence': 90
            },
            'py2exe': {
                'strings': [
                    'py2exe',
                    'PY2EXE_VER',
                    'pythoncom',
                    'pywintypes'
                ],
                'magic_bytes': [
                    b'py2exe'
                ],
                'confidence': 85
            },
            'cx_freeze': {
                'strings': [
                    'cx_Freeze',
                    'cx_Freeze',
                    'freeze'
                ],
                'magic_bytes': [
                    b'cx_Freeze'
                ],
                'confidence': 80
            },
            'themida': {
                'strings': [
                    'Themida',
                    'WinLicense',
                    'ThemidaSDK'
                ],
                'magic_bytes': [],
                'confidence': 75
            },
            'upx': {
                'strings': [
                    'UPX!',
                    'UPX0',
                    'UPX1'
                ],
                'magic_bytes': [
                    b'UPX!'
                ],
                'confidence': 90
            },
            'vmprotect': {
                'strings': [
                    'VMProtect',
                    'VMProtectSDK'
                ],
                'magic_bytes': [],
                'confidence': 70
            }
        }
        return signatures
        
    def _load_yara_rules(self) -> List[yara.Rule]:
        """Load YARA rules for advanced detection."""
        rules = []
        
        # PyInstaller rule
        pyinstaller_rule = """
        rule PyInstaller {
            strings:
                $pyiboot = "pyiboot" nocase
                $pyimod = "pyimod" nocase
                $pyz = "PYZ-" wide ascii
                $pyinstaller = "PyInstaller" nocase
            condition:
                any of them
        }
        """
        
        # PyArmor rule
        pyarmor_rule = """
        rule PyArmor {
            strings:
                $pyarmor = "pyarmor" nocase
                $pytransform = "_pytransform" nocase
                $pytransform_dll = "pytransform.dll" nocase
            condition:
                any of them
        }
        """
        
        # UPX rule
        upx_rule = """
        rule UPX {
            strings:
                $upx = "UPX!" ascii
                $upx0 = "UPX0" ascii
                $upx1 = "UPX1" ascii
            condition:
                any of them
        }
        """
        
        try:
            rules.append(yara.compile(source=pyinstaller_rule))
            rules.append(yara.compile(source=pyarmor_rule))
            rules.append(yara.compile(source=upx_rule))
        except Exception as e:
            print(f"Warning: Failed to compile YARA rules: {e}")
            
        return rules
        
    def detect_packer(self, file_path: Path) -> Optional[Dict]:
        """
        Detect packer/protection in the target file.
        
        Args:
            file_path: Path to the target executable
            
        Returns:
            Dictionary with detection results or None
        """
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
                
            # Method 1: String-based detection
            string_matches = self._detect_by_strings(content)
            
            # Method 2: PE header analysis
            pe_matches = self._detect_by_pe_headers(file_path)
            
            # Method 3: YARA rules
            yara_matches = self._detect_by_yara(content)
            
            # Method 4: Magic bytes
            magic_matches = self._detect_by_magic_bytes(content)
            
            # Combine results
            all_matches = {}
            
            for match_type, matches in [
                ('strings', string_matches),
                ('pe_headers', pe_matches),
                ('yara', yara_matches),
                ('magic_bytes', magic_matches)
            ]:
                for packer, confidence in matches.items():
                    if packer not in all_matches:
                        all_matches[packer] = {'confidence': 0, 'methods': []}
                    all_matches[packer]['confidence'] = max(all_matches[packer]['confidence'], confidence)
                    all_matches[packer]['methods'].append(match_type)
                    
            # Return the best match
            if all_matches:
                best_match = max(all_matches.items(), key=lambda x: x[1]['confidence'])
                return {
                    'packer': best_match[0],
                    'confidence': best_match[1]['confidence'],
                    'detection_methods': best_match[1]['methods'],
                    'all_matches': all_matches
                }
                
        except Exception as e:
            print(f"Error during packer detection: {e}")
            
        return None
        
    def _detect_by_strings(self, content: bytes) -> Dict[str, int]:
        """Detect packers by searching for characteristic strings."""
        matches = {}
        content_str = content.decode('utf-8', errors='ignore')
        
        for packer, signature in self.signatures.items():
            confidence = 0
            for string in signature['strings']:
                if string.lower() in content_str.lower():
                    confidence = max(confidence, signature['confidence'])
                    
            if confidence > 0:
                matches[packer] = confidence
                
        return matches
        
    def _detect_by_pe_headers(self, file_path: Path) -> Dict[str, int]:
        """Detect packers by analyzing PE headers and sections."""
        matches = {}
        
        try:
            pe = pefile.PE(file_path)
            
            # Check for suspicious section names
            suspicious_sections = {
                'pyarmor': ['pyarmor', 'pytransform'],
                'themida': ['themida', 'winlicense'],
                'vmprotect': ['vmprotect', 'vmp'],
                'upx': ['upx0', 'upx1']
            }
            
            for section in pe.sections:
                section_name = section.Name.decode('utf-8').rstrip('\x00').lower()
                
                for packer, keywords in suspicious_sections.items():
                    for keyword in keywords:
                        if keyword in section_name:
                            matches[packer] = self.signatures.get(packer, {}).get('confidence', 70)
                            
            # Check for suspicious imports
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    
                    if 'pytransform' in dll_name:
                        matches['pyarmor'] = self.signatures['pyarmor']['confidence']
                    elif 'themida' in dll_name:
                        matches['themida'] = self.signatures['themida']['confidence']
                        
        except Exception as e:
            print(f"Error analyzing PE headers: {e}")
            
        return matches
        
    def _detect_by_yara(self, content: bytes) -> Dict[str, int]:
        """Detect packers using YARA rules."""
        matches = {}
        
        for rule in self.yara_rules:
            try:
                rule_matches = rule.match(data=content)
                for match in rule_matches:
                    rule_name = match.rule.lower()
                    if 'pyinstaller' in rule_name:
                        matches['pyinstaller'] = self.signatures['pyinstaller']['confidence']
                    elif 'pyarmor' in rule_name:
                        matches['pyarmor'] = self.signatures['pyarmor']['confidence']
                    elif 'upx' in rule_name:
                        matches['upx'] = self.signatures['upx']['confidence']
            except Exception as e:
                print(f"Error in YARA rule {rule}: {e}")
                
        return matches
        
    def _detect_by_magic_bytes(self, content: bytes) -> Dict[str, int]:
        """Detect packers by searching for magic bytes."""
        matches = {}
        
        for packer, signature in self.signatures.items():
            for magic in signature.get('magic_bytes', []):
                if magic in content:
                    matches[packer] = signature['confidence']
                    
        return matches
        
    def get_packer_info(self, packer_name: str) -> Dict:
        """Get detailed information about a detected packer."""
        packer_info = {
            'pyinstaller': {
                'name': 'PyInstaller',
                'description': 'Python application packer that bundles Python applications into standalone executables',
                'extraction_method': 'pyinstxtractor-ng compatible extraction',
                'difficulty': 'Easy',
                'protection_level': 'Low'
            },
            'pyarmor': {
                'name': 'PyArmor',
                'description': 'Advanced Python code protection and licensing tool',
                'extraction_method': 'Runtime hooking and memory dumping',
                'difficulty': 'Hard',
                'protection_level': 'High'
            },
            'py2exe': {
                'name': 'py2exe',
                'description': 'Python to executable converter',
                'extraction_method': 'Direct extraction from resources',
                'difficulty': 'Easy',
                'protection_level': 'Low'
            },
            'cx_freeze': {
                'name': 'cx_Freeze',
                'description': 'Python packaging tool for creating executables',
                'extraction_method': 'Resource extraction',
                'difficulty': 'Medium',
                'protection_level': 'Medium'
            },
            'themida': {
                'name': 'Themida',
                'description': 'Advanced Windows software protection system',
                'extraction_method': 'Anti-debug bypass and memory analysis',
                'difficulty': 'Very Hard',
                'protection_level': 'Very High'
            },
            'upx': {
                'name': 'UPX',
                'description': 'Ultimate Packer for eXecutables',
                'extraction_method': 'Standard UPX unpacking',
                'difficulty': 'Easy',
                'protection_level': 'Low'
            },
            'vmprotect': {
                'name': 'VMProtect',
                'description': 'Software virtualization and protection tool',
                'extraction_method': 'Virtual machine analysis',
                'difficulty': 'Very Hard',
                'protection_level': 'Very High'
            }
        }
        
        return packer_info.get(packer_name.lower(), {
            'name': 'Unknown',
            'description': 'Unknown packer or protection',
            'extraction_method': 'Generic analysis',
            'difficulty': 'Unknown',
            'protection_level': 'Unknown'
        }) 