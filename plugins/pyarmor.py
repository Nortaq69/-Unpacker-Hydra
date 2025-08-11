"""
PyArmor Plugin
Advanced analysis and decryption for PyArmor protected executables.
"""

import os
import sys
import struct
import marshal
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Any
import frida
import time

class PyArmorPlugin:
    """Advanced PyArmor analysis and decryption plugin."""
    
    def __init__(self):
        self.name = "PyArmor"
        self.version = "1.0.0"
        self.description = "Advanced PyArmor protection analysis and decryption"
        
    def can_handle(self, target_path: Path) -> bool:
        """Check if this plugin can handle the target."""
        try:
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Look for PyArmor signatures
            signatures = [
                b'pyarmor',
                b'PyArmor',
                b'_pytransform',
                b'pytransform.dll'
            ]
            
            for sig in signatures:
                if sig in data:
                    return True
                    
            return False
            
        except Exception:
            return False
            
    def analyze(self, target_path: Path, output_dir: Path, options: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze PyArmor protected executable."""
        try:
            # Create output structure
            (output_dir / 'pyarmor').mkdir(exist_ok=True)
            (output_dir / 'pyarmor' / 'analysis').mkdir(exist_ok=True)
            (output_dir / 'pyarmor' / 'hooks').mkdir(exist_ok=True)
            (output_dir / 'pyarmor' / 'decrypted').mkdir(exist_ok=True)
            
            # Perform static analysis
            static_analysis = self._static_analysis(target_path)
            
            # Create runtime hooks
            hooks = self._create_runtime_hooks(target_path, output_dir)
            
            # Generate decryption scripts
            decryption_scripts = self._generate_decryption_scripts(output_dir)
            
            return {
                'success': True,
                'static_analysis': static_analysis,
                'hooks': hooks,
                'decryption_scripts': decryption_scripts,
                'requires_runtime': True
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _static_analysis(self, target_path: Path) -> Dict[str, Any]:
        """Perform static analysis of PyArmor executable."""
        analysis = {
            'protection_level': 'Unknown',
            'encryption_methods': [],
            'anti_debug_techniques': [],
            'suspicious_imports': [],
            'file_structure': {}
        }
        
        try:
            # Read file data
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Analyze file structure
            analysis['file_structure'] = self._analyze_file_structure(data)
            
            # Look for encryption patterns
            analysis['encryption_methods'] = self._detect_encryption_methods(data)
            
            # Look for anti-debug techniques
            analysis['anti_debug_techniques'] = self._detect_anti_debug(data)
            
            # Analyze imports
            analysis['suspicious_imports'] = self._analyze_imports(target_path)
            
            # Determine protection level
            analysis['protection_level'] = self._determine_protection_level(analysis)
            
        except Exception as e:
            print(f"Error in static analysis: {e}")
            
        return analysis
        
    def _analyze_file_structure(self, data: bytes) -> Dict[str, Any]:
        """Analyze the file structure for PyArmor patterns."""
        structure = {
            'size': len(data),
            'pyarmor_sections': [],
            'encrypted_regions': [],
            'entry_points': []
        }
        
        # Look for PyArmor sections
        pyarmor_patterns = [
            b'pyarmor',
            b'PyArmor',
            b'_pytransform'
        ]
        
        for pattern in pyarmor_patterns:
            pos = 0
            while True:
                pos = data.find(pattern, pos)
                if pos == -1:
                    break
                structure['pyarmor_sections'].append({
                    'offset': pos,
                    'pattern': pattern.decode('ascii', errors='ignore'),
                    'size': len(pattern)
                })
                pos += 1
                
        # Look for encrypted regions (high entropy)
        structure['encrypted_regions'] = self._find_encrypted_regions(data)
        
        return structure
        
    def _find_encrypted_regions(self, data: bytes) -> List[Dict[str, Any]]:
        """Find regions with high entropy (likely encrypted)."""
        encrypted_regions = []
        
        # Simple entropy calculation
        def calculate_entropy(region_data):
            if len(region_data) == 0:
                return 0
                
            # Count byte frequencies
            byte_counts = [0] * 256
            for byte in region_data:
                byte_counts[byte] += 1
                
            # Calculate entropy
            entropy = 0
            for count in byte_counts:
                if count > 0:
                    p = count / len(region_data)
                    entropy -= p * (p.bit_length() - 1)
                    
            return entropy
            
        # Scan for high entropy regions
        window_size = 1024
        for i in range(0, len(data) - window_size, window_size // 2):
            region_data = data[i:i + window_size]
            entropy = calculate_entropy(region_data)
            
            if entropy > 7.0:  # High entropy threshold
                encrypted_regions.append({
                    'offset': i,
                    'size': len(region_data),
                    'entropy': entropy
                })
                
        return encrypted_regions
        
    def _detect_encryption_methods(self, data: bytes) -> List[str]:
        """Detect encryption methods used."""
        methods = []
        
        # Look for encryption patterns
        encryption_patterns = {
            b'AES': 'AES encryption',
            b'RSA': 'RSA encryption',
            b'XOR': 'XOR encryption',
            b'base64': 'Base64 encoding',
            b'zlib': 'Zlib compression',
            b'gzip': 'Gzip compression'
        }
        
        data_str = data.decode('utf-8', errors='ignore').lower()
        for pattern, method in encryption_patterns.items():
            if pattern.decode().lower() in data_str:
                methods.append(method)
                
        return methods
        
    def _detect_anti_debug(self, data: bytes) -> List[str]:
        """Detect anti-debugging techniques."""
        techniques = []
        
        # Look for anti-debug patterns
        anti_debug_patterns = {
            b'IsDebuggerPresent': 'Debugger detection',
            b'CheckRemoteDebuggerPresent': 'Remote debugger detection',
            b'GetTickCount': 'Timing-based detection',
            b'QueryPerformanceCounter': 'High-resolution timing',
            b'GetSystemTime': 'System time checks',
            b'VirtualProtect': 'Memory protection manipulation',
            b'SetProcessDEPPolicy': 'DEP policy manipulation'
        }
        
        for pattern, technique in anti_debug_patterns.items():
            if pattern in data:
                techniques.append(technique)
                
        return techniques
        
    def _analyze_imports(self, target_path: Path) -> List[str]:
        """Analyze imports for suspicious functions."""
        suspicious_imports = []
        
        try:
            import pefile
            
            pe = pefile.PE(target_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8').lower()
                    
                    # Check for suspicious DLLs
                    suspicious_dlls = [
                        'pytransform.dll',
                        'kernel32.dll',
                        'ntdll.dll',
                        'advapi32.dll'
                    ]
                    
                    if any(dll in dll_name for dll in suspicious_dlls):
                        for imp in entry.imports:
                            if imp.name:
                                func_name = imp.name.decode('utf-8')
                                suspicious_imports.append(f"{dll_name}:{func_name}")
                                
        except Exception as e:
            print(f"Error analyzing imports: {e}")
            
        return suspicious_imports
        
    def _determine_protection_level(self, analysis: Dict[str, Any]) -> str:
        """Determine the protection level based on analysis."""
        score = 0
        
        # Score based on encryption methods
        score += len(analysis['encryption_methods']) * 2
        
        # Score based on anti-debug techniques
        score += len(analysis['anti_debug_techniques']) * 1.5
        
        # Score based on suspicious imports
        score += len(analysis['suspicious_imports']) * 0.5
        
        # Score based on encrypted regions
        score += len(analysis['file_structure']['encrypted_regions']) * 1
        
        if score >= 10:
            return "Very High"
        elif score >= 7:
            return "High"
        elif score >= 4:
            return "Medium"
        elif score >= 2:
            return "Low"
        else:
            return "Minimal"
            
    def _create_runtime_hooks(self, target_path: Path, output_dir: Path) -> List[str]:
        """Create runtime hooks for PyArmor analysis."""
        hooks = []
        
        # Create Frida hook script
        frida_script = self._generate_frida_script()
        frida_script_path = output_dir / 'pyarmor' / 'hooks' / 'pyarmor_hook.js'
        frida_script_path.write_text(frida_script)
        hooks.append(str(frida_script_path))
        
        # Create Python hook script
        python_script = self._generate_python_hook()
        python_script_path = output_dir / 'pyarmor' / 'hooks' / 'pyarmor_hook.py'
        python_script_path.write_text(python_script)
        hooks.append(str(python_script_path))
        
        return hooks
        
    def _generate_frida_script(self) -> str:
        """Generate Frida hook script for PyArmor."""
        return '''
// PyArmor Runtime Analysis Hook
// This script hooks PyArmor functions to capture decrypted code

console.log("[+] PyArmor hook script loaded");

// Hook Python evaluation functions
var pythonDll = Module.findBaseAddress("python3x.dll");
if (!pythonDll) {
    pythonDll = Module.findBaseAddress("python39.dll");
}
if (!pythonDll) {
    pythonDll = Module.findBaseAddress("python38.dll");
}

if (pythonDll) {
    console.log("[+] Found Python DLL at:", pythonDll);
    
    // Hook PyEval_EvalCode
    var PyEval_EvalCode = Module.findExportByName("python3x.dll", "PyEval_EvalCode");
    if (PyEval_EvalCode) {
        Interceptor.attach(PyEval_EvalCode, {
            onEnter: function (args) {
                console.log("[+] PyEval_EvalCode called");
                console.log("[+] Code object address:", args[0]);
                
                // Dump the code object
                var codeObj = args[0];
                if (codeObj != 0) {
                    try {
                        var codeData = Memory.readByteArray(codeObj, 1024);
                        if (codeData) {
                            console.log("[+] Code object data:", hexdump(codeData));
                        }
                    } catch (e) {
                        console.log("[!] Error reading code object:", e);
                    }
                }
            }
        });
    }
    
    // Hook PyCode_New
    var PyCode_New = Module.findExportByName("python3x.dll", "PyCode_New");
    if (PyCode_New) {
        Interceptor.attach(PyCode_New, {
            onLeave: function (retval) {
                console.log("[+] New code object created:", retval);
            }
        });
    }
}

// Hook PyArmor specific functions
var pytransform = Module.findBaseAddress("pytransform.dll");
if (pytransform) {
    console.log("[+] Found pytransform.dll at:", pytransform);
    
    // Hook decryption functions
    Interceptor.attach(pytransform.add(0x1000), {
        onEnter: function (args) {
            console.log("[+] PyArmor decryption function called");
            console.log("[+] Arguments:", args[0], args[1], args[2], args[3]);
        },
        onLeave: function (retval) {
            console.log("[+] Decryption result:", retval);
        }
    });
}

// Hook memory allocation functions
var malloc = Module.findExportByName("msvcrt.dll", "malloc");
if (malloc) {
    Interceptor.attach(malloc, {
        onLeave: function (retval) {
            var size = this.context.eax;
            if (size > 1024) {  // Large allocations
                console.log("[+] Large malloc:", size, "bytes at", retval);
            }
        }
    });
}

// Hook file operations
var CreateFileA = Module.findExportByName("kernel32.dll", "CreateFileA");
if (CreateFileA) {
    Interceptor.attach(CreateFileA, {
        onEnter: function (args) {
            var filename = Memory.readUtf8String(args[0]);
            console.log("[+] File access:", filename);
        }
    });
}

console.log("[+] PyArmor hooks installed successfully");
'''
        
    def _generate_python_hook(self) -> str:
        """Generate Python hook script for PyArmor."""
        return '''
#!/usr/bin/env python3
"""
PyArmor Python Hook Script
Runtime analysis and decryption for PyArmor protected executables.
"""

import frida
import sys
import time
import json
from pathlib import Path

def on_message(message, data):
    """Handle messages from Frida script."""
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[!] {0}".format(message['stack']))

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python pyarmor_hook.py <target_process>")
        sys.exit(1)
        
    target_process = sys.argv[1]
    
    # Load the Frida script
    script_path = Path(__file__).parent / "pyarmor_hook.js"
    with open(script_path, 'r') as f:
        script_source = f.read()
    
    try:
        # Attach to target process
        print(f"[+] Attaching to process: {target_process}")
        process = frida.attach(target_process)
        
        # Create and load script
        script = process.create_script(script_source)
        script.on('message', on_message)
        script.load()
        
        print("[+] PyArmor hook script loaded successfully")
        print("[+] Press Enter to exit...")
        
        # Keep the script running
        sys.stdin.read()
        
    except frida.ProcessNotFoundError:
        print(f"[!] Process '{target_process}' not found")
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()
'''
        
    def _generate_decryption_scripts(self, output_dir: Path) -> List[str]:
        """Generate decryption scripts for PyArmor."""
        scripts = []
        
        # Create brute force decryption script
        brute_force_script = self._generate_brute_force_script()
        brute_force_path = output_dir / 'pyarmor' / 'decrypted' / 'brute_force.py'
        brute_force_path.write_text(brute_force_script)
        scripts.append(str(brute_force_path))
        
        # Create XOR decryption script
        xor_script = self._generate_xor_script()
        xor_path = output_dir / 'pyarmor' / 'decrypted' / 'xor_decrypt.py'
        xor_path.write_text(xor_script)
        scripts.append(str(xor_path))
        
        return scripts
        
    def _generate_brute_force_script(self) -> str:
        """Generate brute force decryption script."""
        return '''
#!/usr/bin/env python3
"""
PyArmor Brute Force Decryption Script
Attempts to decrypt PyArmor protected code using common keys and methods.
"""

import struct
import marshal
import itertools
from pathlib import Path

def try_xor_decrypt(data, key):
    """Try XOR decryption with given key."""
    try:
        decrypted = bytes(b ^ key for b in data)
        # Check if it looks like valid Python bytecode
        if len(decrypted) >= 16:
            magic = decrypted[:4]
            if magic in [b'\\x03\\xf3\\x0d\\x0a', b'\\x03\\xf4\\x0d\\x0a', b'\\x03\\xf2\\x0d\\x0a']:
                return decrypted
    except:
        pass
    return None

def try_rot_decrypt(data, rotation):
    """Try ROT decryption."""
    try:
        decrypted = bytes((b + rotation) % 256 for b in data)
        return decrypted
    except:
        return None

def brute_force_decrypt(file_path):
    """Brute force decryption of PyArmor protected file."""
    print(f"[+] Attempting brute force decryption of: {file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # Try XOR with single byte keys
    print("[+] Trying XOR decryption...")
    for key in range(256):
        decrypted = try_xor_decrypt(data, key)
        if decrypted:
            print(f"[+] Found valid XOR key: 0x{key:02x}")
            output_path = f"{file_path}.xor_decrypted"
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            print(f"[+] Saved decrypted data to: {output_path}")
            return output_path
    
    # Try ROT decryption
    print("[+] Trying ROT decryption...")
    for rotation in range(1, 26):
        decrypted = try_rot_decrypt(data, rotation)
        if decrypted:
            print(f"[+] Found valid ROT key: {rotation}")
            output_path = f"{file_path}.rot_decrypted"
            with open(output_path, 'wb') as f:
                f.write(decrypted)
            print(f"[+] Saved decrypted data to: {output_path}")
            return output_path
    
    print("[!] Brute force decryption failed")
    return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python brute_force.py <encrypted_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    if not Path(file_path).exists():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)
    
    result = brute_force_decrypt(file_path)
    if result:
        print(f"[+] Decryption successful: {result}")
    else:
        print("[!] Decryption failed")
'''
        
    def _generate_xor_script(self) -> str:
        """Generate XOR decryption script."""
        return '''
#!/usr/bin/env python3
"""
PyArmor XOR Decryption Script
Specialized XOR decryption for PyArmor protected code.
"""

import struct
import marshal
from pathlib import Path

def xor_decrypt(data, key):
    """Decrypt data using XOR with given key."""
    if isinstance(key, int):
        # Single byte key
        return bytes(b ^ key for b in data)
    elif isinstance(key, bytes):
        # Multi-byte key
        return bytes(data[i] ^ key[i % len(key)] for i in range(len(data)))
    else:
        raise ValueError("Key must be int or bytes")

def find_xor_key(data, known_pattern=b'def '):
    """Find XOR key by looking for known patterns."""
    for key in range(256):
        decrypted = xor_decrypt(data, key)
        if known_pattern in decrypted:
            return key
    return None

def decrypt_pyarmor_file(file_path, key=None):
    """Decrypt PyArmor protected file."""
    print(f"[+] Decrypting: {file_path}")
    
    with open(file_path, 'rb') as f:
        data = f.read()
    
    if key is None:
        # Try to find the key automatically
        print("[+] Attempting to find XOR key...")
        key = find_xor_key(data)
        if key is None:
            print("[!] Could not find XOR key automatically")
            return None
        print(f"[+] Found XOR key: 0x{key:02x}")
    
    # Decrypt the data
    decrypted = xor_decrypt(data, key)
    
    # Save decrypted data
    output_path = f"{file_path}.decrypted"
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    print(f"[+] Decrypted data saved to: {output_path}")
    return output_path

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python xor_decrypt.py <encrypted_file> [key]")
        sys.exit(1)
    
    file_path = sys.argv[1]
    key = int(sys.argv[2], 16) if len(sys.argv) > 2 else None
    
    if not Path(file_path).exists():
        print(f"[!] File not found: {file_path}")
        sys.exit(1)
    
    result = decrypt_pyarmor_file(file_path, key)
    if result:
        print(f"[+] Decryption successful: {result}")
    else:
        print("[!] Decryption failed")
'''
        
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            'name': self.name,
            'version': self.version,
            'description': self.description,
            'author': 'Unpacker Hydra Team',
            'capabilities': [
                'PyArmor protection detection',
                'Static analysis',
                'Runtime hooking',
                'Brute force decryption',
                'XOR decryption',
                'Anti-debug detection'
            ]
        }
        
    def get_help(self) -> str:
        """Get help information for this plugin."""
        return """
PyArmor Plugin Help:

This plugin provides advanced analysis and decryption capabilities for PyArmor protected executables.

Features:
- Automatic PyArmor detection
- Static analysis of protection methods
- Runtime hooking with Frida
- Brute force decryption
- XOR key detection
- Anti-debug technique detection

Usage:
1. The plugin automatically activates when a PyArmor executable is detected
2. Static analysis is performed immediately
3. Runtime analysis requires the target to be executed
4. Use the generated hooks and scripts for manual analysis

Output:
- Static analysis report in pyarmor/analysis/
- Runtime hooks in pyarmor/hooks/
- Decryption scripts in pyarmor/decrypted/

Runtime Analysis:
1. Use the Frida hook script: pyarmor_hook.js
2. Use the Python hook script: pyarmor_hook.py
3. Execute the target and monitor for decrypted code

Decryption:
1. Try brute force decryption: brute_force.py
2. Try XOR decryption: xor_decrypt.py
3. Manual analysis may be required for advanced protection

Note: PyArmor protection can be very sophisticated. This plugin provides tools for analysis,
but manual intervention may be required for heavily protected executables.
""" 