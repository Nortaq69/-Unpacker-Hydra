"""
Pattern Matching Utility Module
Advanced pattern detection for obfuscation and protection analysis.
"""

import re
import struct
import binascii
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import yara

class PatternMatcher:
    """Advanced pattern matching for reverse engineering analysis."""
    
    def __init__(self):
        self.patterns = self._load_patterns()
        self.yara_rules = self._load_yara_rules()
        
    def _load_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Load pattern definitions for various protection types."""
        patterns = {
            'python_bytecode': {
                'magic_numbers': [
                    b'\x03\xf3\x0d\x0a',  # Python 3.7+
                    b'\x03\xf4\x0d\x0a',  # Python 3.8+
                    b'\x03\xf2\x0d\x0a',  # Python 3.2
                    b'\x03\xf1\x0d\x0a',  # Python 3.1
                    b'\x03\xf0\x0d\x0a',  # Python 3.0
                ],
                'description': 'Python bytecode files',
                'confidence': 95
            },
            'pyinstaller': {
                'strings': [
                    'PyInstaller',
                    'pyiboot',
                    'pyimod',
                    'PYZ-00.pyz',
                    'PYZ-01.pyz'
                ],
                'description': 'PyInstaller executable',
                'confidence': 90
            },
            'pyarmor': {
                'strings': [
                    'pyarmor',
                    'PyArmor',
                    '_pytransform',
                    'pytransform.dll'
                ],
                'description': 'PyArmor protection',
                'confidence': 85
            },
            'upx': {
                'magic_numbers': [b'UPX!'],
                'strings': ['UPX0', 'UPX1'],
                'description': 'UPX compression',
                'confidence': 95
            },
            'themida': {
                'strings': [
                    'Themida',
                    'WinLicense',
                    'ThemidaSDK'
                ],
                'description': 'Themida protection',
                'confidence': 80
            },
            'vmprotect': {
                'strings': [
                    'VMProtect',
                    'VMProtectSDK'
                ],
                'description': 'VMProtect virtualization',
                'confidence': 75
            },
            'xor_encryption': {
                'patterns': [
                    r'\\x[0-9a-fA-F]{2}',  # Hex patterns
                    r'[\\x00-\\xff]{4,}',   # Binary data
                ],
                'description': 'XOR encryption',
                'confidence': 60
            },
            'base64_encoding': {
                'patterns': [
                    r'[A-Za-z0-9+/]{4,}={0,2}',  # Base64 pattern
                ],
                'description': 'Base64 encoding',
                'confidence': 70
            },
            'anti_debug': {
                'strings': [
                    'IsDebuggerPresent',
                    'CheckRemoteDebuggerPresent',
                    'GetTickCount',
                    'QueryPerformanceCounter',
                    'VirtualProtect',
                    'SetProcessDEPPolicy'
                ],
                'description': 'Anti-debugging techniques',
                'confidence': 75
            },
            'string_encryption': {
                'patterns': [
                    r'[A-Z]{4,}',  # All caps strings
                    r'[\\x00-\\xff]{8,}',  # Binary strings
                ],
                'description': 'String encryption',
                'confidence': 65
            }
        }
        return patterns
        
    def _load_yara_rules(self) -> List[yara.Rule]:
        """Load YARA rules for advanced pattern matching."""
        rules = []
        
        # Python bytecode rule
        python_rule = """
        rule PythonBytecode {
            meta:
                description = "Python bytecode detection"
                author = "Unpacker Hydra"
            strings:
                $pyc_magic_37 = { 03 F3 0D 0A }  // Python 3.7+
                $pyc_magic_38 = { 03 F4 0D 0A }  // Python 3.8+
                $pyc_magic_32 = { 03 F2 0D 0A }  // Python 3.2
                $pyc_magic_31 = { 03 F1 0D 0A }  // Python 3.1
                $pyc_magic_30 = { 03 F0 0D 0A }  // Python 3.0
            condition:
                any of them
        }
        """
        
        # PyInstaller rule
        pyinstaller_rule = """
        rule PyInstaller {
            meta:
                description = "PyInstaller executable detection"
                author = "Unpacker Hydra"
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
            meta:
                description = "PyArmor protection detection"
                author = "Unpacker Hydra"
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
            meta:
                description = "UPX compression detection"
                author = "Unpacker Hydra"
            strings:
                $upx = "UPX!" ascii
                $upx0 = "UPX0" ascii
                $upx1 = "UPX1" ascii
            condition:
                any of them
        }
        """
        
        # Anti-debug rule
        antidebug_rule = """
        rule AntiDebug {
            meta:
                description = "Anti-debugging technique detection"
                author = "Unpacker Hydra"
            strings:
                $isdebugger = "IsDebuggerPresent" ascii
                $checkremote = "CheckRemoteDebuggerPresent" ascii
                $gettick = "GetTickCount" ascii
                $queryperf = "QueryPerformanceCounter" ascii
                $virtualprotect = "VirtualProtect" ascii
            condition:
                2 of them
        }
        """
        
        try:
            rules.extend([
                yara.compile(source=python_rule),
                yara.compile(source=pyinstaller_rule),
                yara.compile(source=pyarmor_rule),
                yara.compile(source=upx_rule),
                yara.compile(source=antidebug_rule)
            ])
        except Exception as e:
            print(f"Warning: Failed to compile YARA rules: {e}")
            
        return rules
        
    def scan_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Scan a file for various patterns.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary with scan results
        """
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            return self.scan_data(data, str(file_path))
            
        except Exception as e:
            return {'error': str(e)}
            
    def scan_data(self, data: bytes, context: str = "unknown") -> Dict[str, Any]:
        """
        Scan binary data for patterns.
        
        Args:
            data: Binary data to scan
            context: Context string for the data
            
        Returns:
            Dictionary with scan results
        """
        results = {
            'context': context,
            'size': len(data),
            'patterns_found': [],
            'yara_matches': [],
            'entropy_analysis': self._analyze_entropy(data),
            'string_analysis': self._analyze_strings(data)
        }
        
        # Scan for defined patterns
        for pattern_name, pattern_info in self.patterns.items():
            matches = self._check_pattern(data, pattern_name, pattern_info)
            if matches:
                results['patterns_found'].append({
                    'pattern': pattern_name,
                    'description': pattern_info['description'],
                    'confidence': pattern_info['confidence'],
                    'matches': matches
                })
                
        # Apply YARA rules
        for rule in self.yara_rules:
            try:
                rule_matches = rule.match(data=data)
                for match in rule_matches:
                    results['yara_matches'].append({
                        'rule': match.rule,
                        'strings': [str(s) for s in match.strings],
                        'meta': match.meta
                    })
            except Exception as e:
                print(f"Error applying YARA rule {rule}: {e}")
                
        return results
        
    def _check_pattern(self, data: bytes, pattern_name: str, pattern_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for a specific pattern in the data."""
        matches = []
        
        # Check magic numbers
        if 'magic_numbers' in pattern_info:
            for magic in pattern_info['magic_numbers']:
                pos = 0
                while True:
                    pos = data.find(magic, pos)
                    if pos == -1:
                        break
                    matches.append({
                        'type': 'magic_number',
                        'offset': pos,
                        'value': magic.hex(),
                        'size': len(magic)
                    })
                    pos += 1
                    
        # Check strings
        if 'strings' in pattern_info:
            data_str = data.decode('utf-8', errors='ignore')
            for string in pattern_info['strings']:
                pos = 0
                while True:
                    pos = data_str.find(string, pos)
                    if pos == -1:
                        break
                    matches.append({
                        'type': 'string',
                        'offset': pos,
                        'value': string,
                        'size': len(string)
                    })
                    pos += 1
                    
        # Check regex patterns
        if 'patterns' in pattern_info:
            data_str = data.decode('utf-8', errors='ignore')
            for pattern in pattern_info['patterns']:
                for match in re.finditer(pattern, data_str):
                    matches.append({
                        'type': 'regex',
                        'offset': match.start(),
                        'value': match.group(),
                        'size': len(match.group())
                    })
                    
        return matches
        
    def _analyze_entropy(self, data: bytes) -> Dict[str, Any]:
        """Analyze data entropy."""
        if len(data) == 0:
            return {'entropy': 0, 'entropy_level': 'unknown'}
            
        # Calculate byte frequency
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
            
        # Calculate entropy
        entropy = 0
        for count in byte_counts:
            if count > 0:
                p = count / len(data)
                entropy -= p * (p.bit_length() - 1)
                
        # Determine entropy level
        if entropy > 7.5:
            level = 'high'
        elif entropy > 6.0:
            level = 'medium'
        else:
            level = 'low'
            
        return {
            'entropy': entropy,
            'entropy_level': level,
            'unique_bytes': sum(1 for count in byte_counts if count > 0)
        }
        
    def _analyze_strings(self, data: bytes) -> Dict[str, Any]:
        """Analyze strings in the data."""
        strings = []
        current_string = ""
        
        # Extract ASCII strings
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= 4:  # Minimum string length
                    strings.append(current_string)
                current_string = ""
                
        # Add the last string if it's long enough
        if len(current_string) >= 4:
            strings.append(current_string)
            
        # Analyze string characteristics
        string_analysis = {
            'total_strings': len(strings),
            'longest_string': max(len(s) for s in strings) if strings else 0,
            'average_length': sum(len(s) for s in strings) / len(strings) if strings else 0,
            'suspicious_strings': []
        }
        
        # Look for suspicious strings
        suspicious_patterns = [
            r'[A-Z]{8,}',  # All caps long strings
            r'[\\x00-\\xff]{8,}',  # Binary strings
            r'[0-9a-fA-F]{16,}',  # Hex strings
        ]
        
        for string in strings:
            for pattern in suspicious_patterns:
                if re.match(pattern, string):
                    string_analysis['suspicious_strings'].append({
                        'string': string,
                        'pattern': pattern,
                        'length': len(string)
                    })
                    break
                    
        return string_analysis
        
    def find_xor_key(self, data: bytes, known_pattern: bytes = b'def ') -> Optional[int]:
        """
        Find XOR key by looking for known patterns.
        
        Args:
            data: Encrypted data
            known_pattern: Known pattern to search for
            
        Returns:
            XOR key if found, None otherwise
        """
        for key in range(256):
            decrypted = bytes(b ^ key for b in data)
            if known_pattern in decrypted:
                return key
        return None
        
    def find_rot_key(self, data: bytes, known_pattern: bytes = b'def ') -> Optional[int]:
        """
        Find ROT key by looking for known patterns.
        
        Args:
            data: Encrypted data
            known_pattern: Known pattern to search for
            
        Returns:
            ROT key if found, None otherwise
        """
        for rotation in range(1, 256):
            decrypted = bytes((b + rotation) % 256 for b in data)
            if known_pattern in decrypted:
                return rotation
        return None
        
    def detect_obfuscation(self, data: bytes) -> Dict[str, Any]:
        """
        Detect obfuscation techniques in the data.
        
        Args:
            data: Data to analyze
            
        Returns:
            Dictionary with obfuscation detection results
        """
        obfuscation_results = {
            'nop_padding': False,
            'opcode_shifting': False,
            'string_encryption': False,
            'control_flow_obfuscation': False,
            'dead_code_injection': False,
            'confidence_scores': {}
        }
        
        # Check for NOP padding
        nop_count = data.count(b'\x09\x00')  # NOP instruction
        total_instructions = len(data) // 2
        if total_instructions > 0 and nop_count / total_instructions > 0.2:
            obfuscation_results['nop_padding'] = True
            obfuscation_results['confidence_scores']['nop_padding'] = 85
            
        # Check for string encryption
        string_analysis = self._analyze_strings(data)
        if string_analysis['suspicious_strings']:
            obfuscation_results['string_encryption'] = True
            obfuscation_results['confidence_scores']['string_encryption'] = 70
            
        # Check for control flow obfuscation (excessive jumps)
        jump_count = 0
        for i in range(0, len(data) - 1, 2):
            if i < len(data):
                opcode = data[i]
                if opcode in [110, 111, 112, 113, 114]:  # JUMP opcodes
                    jump_count += 1
                    
        if jump_count > len(data) * 0.3:
            obfuscation_results['control_flow_obfuscation'] = True
            obfuscation_results['confidence_scores']['control_flow_obfuscation'] = 75
            
        return obfuscation_results
        
    def extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """
        Extract strings from binary data.
        
        Args:
            data: Binary data
            min_length: Minimum string length
            
        Returns:
            List of extracted strings
        """
        strings = []
        current_string = ""
        
        for byte in data:
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append(current_string)
                current_string = ""
                
        # Add the last string if it's long enough
        if len(current_string) >= min_length:
            strings.append(current_string)
            
        return strings
        
    def find_pattern_offsets(self, data: bytes, pattern: bytes) -> List[int]:
        """
        Find all offsets of a pattern in the data.
        
        Args:
            data: Binary data
            pattern: Pattern to search for
            
        Returns:
            List of offsets where pattern was found
        """
        offsets = []
        pos = 0
        
        while True:
            pos = data.find(pattern, pos)
            if pos == -1:
                break
            offsets.append(pos)
            pos += 1
            
        return offsets
        
    def calculate_checksum(self, data: bytes, algorithm: str = 'sha256') -> str:
        """
        Calculate checksum of data.
        
        Args:
            data: Binary data
            algorithm: Hash algorithm to use
            
        Returns:
            Hexadecimal checksum string
        """
        import hashlib
        
        if algorithm == 'md5':
            return hashlib.md5(data).hexdigest()
        elif algorithm == 'sha1':
            return hashlib.sha1(data).hexdigest()
        elif algorithm == 'sha256':
            return hashlib.sha256(data).hexdigest()
        elif algorithm == 'sha512':
            return hashlib.sha512(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
            
    def create_custom_rule(self, rule_name: str, patterns: List[str], condition: str = "any of them") -> str:
        """
        Create a custom YARA rule.
        
        Args:
            rule_name: Name of the rule
            patterns: List of patterns to match
            condition: YARA condition
            
        Returns:
            YARA rule string
        """
        rule = f"""
        rule {rule_name} {{
            meta:
                description = "Custom rule for {rule_name}"
                author = "Unpacker Hydra"
            strings:
        """
        
        for i, pattern in enumerate(patterns):
            rule += f'    $pattern_{i} = "{pattern}" nocase\n'
            
        rule += f"""
            condition:
                {condition}
        }}
        """
        
        return rule 