"""
Bytecode Deobfuscation Module
Handles decompilation and deobfuscation of Python bytecode files.
"""

import os
import sys
import marshal
import struct
import dis
import ast
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import tempfile
import subprocess

class BytecodeDeobfuscator:
    def __init__(self):
        self.decompilers = self._load_decompilers()
        self.obfuscation_patterns = self._load_obfuscation_patterns()
        
    def _load_decompilers(self) -> Dict:
        """Load available decompilers."""
        decompilers = {}
        
        # Try to import uncompyle6
        try:
            import uncompyle6
            decompilers['uncompyle6'] = uncompyle6
        except ImportError:
            print("Warning: uncompyle6 not available")
            
        # Try to import decompyle3
        try:
            import decompyle3
            decompilers['decompyle3'] = decompyle3
        except ImportError:
            print("Warning: decompyle3 not available")
            
        # Built-in decompiler
        decompilers['builtin'] = self._builtin_decompiler
        
        return decompilers
        
    def _load_obfuscation_patterns(self) -> Dict:
        """Load patterns for detecting obfuscated bytecode."""
        patterns = {
            'nop_padding': {
                'description': 'NOP instruction padding',
                'pattern': b'\x09\x00',  # NOP instruction
                'detection': self._detect_nop_padding
            },
            'opcode_shifting': {
                'description': 'Opcode shifting obfuscation',
                'pattern': None,
                'detection': self._detect_opcode_shifting
            },
            'string_encryption': {
                'description': 'String encryption',
                'pattern': None,
                'detection': self._detect_string_encryption
            },
            'control_flow_obfuscation': {
                'description': 'Control flow obfuscation',
                'pattern': None,
                'detection': self._detect_control_flow_obfuscation
            },
            'dead_code_injection': {
                'description': 'Dead code injection',
                'pattern': None,
                'detection': self._detect_dead_code
            }
        }
        return patterns
        
    def deobfuscate_all(self, pyc_files: List[Path], output_dir: Path) -> Dict:
        """
        Deobfuscate all Python bytecode files.
        
        Args:
            pyc_files: List of .pyc file paths
            output_dir: Output directory for decompiled files
            
        Returns:
            Dictionary with deobfuscation results
        """
        try:
            results = {
                'success': True,
                'decompiled_count': 0,
                'failed_count': 0,
                'deobfuscated_files': [],
                'errors': []
            }
            
            # Create decompiled directory
            decompiled_dir = output_dir / 'decompiled'
            decompiled_dir.mkdir(exist_ok=True)
            
            for pyc_file in pyc_files:
                try:
                    result = self.deobfuscate_file(pyc_file, decompiled_dir)
                    if result['success']:
                        results['decompiled_count'] += 1
                        results['deobfuscated_files'].append(result['output_file'])
                    else:
                        results['failed_count'] += 1
                        results['errors'].append(f"{pyc_file}: {result['error']}")
                        
                except Exception as e:
                    results['failed_count'] += 1
                    results['errors'].append(f"{pyc_file}: {str(e)}")
                    
            return results
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def deobfuscate_file(self, pyc_file: Path, output_dir: Path) -> Dict:
        """
        Deobfuscate a single Python bytecode file.
        
        Args:
            pyc_file: Path to .pyc file
            output_dir: Output directory
            
        Returns:
            Dictionary with deobfuscation results
        """
        try:
            # Read the bytecode file
            with open(pyc_file, 'rb') as f:
                data = f.read()
                
            # Check for obfuscation
            obfuscation_detected = self._detect_obfuscation(data)
            
            # Deobfuscate if needed
            if obfuscation_detected:
                data = self._deobfuscate_bytecode(data, obfuscation_detected)
                
            # Decompile the bytecode
            decompiled_code = self._decompile_bytecode(data)
            
            if not decompiled_code:
                return {'success': False, 'error': 'Failed to decompile bytecode'}
                
            # Write decompiled code
            output_file = output_dir / f"{pyc_file.stem}.py"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(decompiled_code)
                
            return {
                'success': True,
                'output_file': str(output_file),
                'obfuscation_detected': obfuscation_detected,
                'decompiler_used': 'unknown'
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _detect_obfuscation(self, data: bytes) -> List[str]:
        """Detect obfuscation patterns in bytecode."""
        detected_patterns = []
        
        for pattern_name, pattern_info in self.obfuscation_patterns.items():
            try:
                if pattern_info['detection'](data):
                    detected_patterns.append(pattern_name)
            except Exception as e:
                print(f"Error detecting {pattern_name}: {e}")
                
        return detected_patterns
        
    def _detect_nop_padding(self, data: bytes) -> bool:
        """Detect NOP instruction padding."""
        # Count NOP instructions
        nop_count = data.count(b'\x09\x00')
        total_instructions = len(data) // 2
        
        # If more than 20% are NOPs, likely obfuscated
        return nop_count / total_instructions > 0.2 if total_instructions > 0 else False
        
    def _detect_opcode_shifting(self, data: bytes) -> bool:
        """Detect opcode shifting obfuscation."""
        try:
            # Try to parse as bytecode and look for invalid opcodes
            code_obj = marshal.loads(data[16:])  # Skip header
            bytecode = code_obj.co_code
            
            invalid_opcodes = 0
            for i in range(0, len(bytecode), 2):
                opcode = bytecode[i]
                if opcode > 255:  # Invalid opcode
                    invalid_opcodes += 1
                    
            return invalid_opcodes > len(bytecode) * 0.1
            
        except Exception:
            return False
            
    def _detect_string_encryption(self, data: bytes) -> bool:
        """Detect string encryption patterns."""
        # Look for patterns that suggest string encryption
        suspicious_patterns = [
            b'decode',
            b'encode',
            b'base64',
            b'rot13',
            b'xor'
        ]
        
        data_str = data.decode('utf-8', errors='ignore').lower()
        matches = sum(1 for pattern in suspicious_patterns if pattern.decode() in data_str)
        
        return matches >= 2
        
    def _detect_control_flow_obfuscation(self, data: bytes) -> bool:
        """Detect control flow obfuscation."""
        try:
            code_obj = marshal.loads(data[16:])
            bytecode = code_obj.co_code
            
            # Look for excessive jumps
            jump_count = 0
            for i in range(0, len(bytecode), 2):
                opcode = bytecode[i]
                if opcode in [110, 111, 112, 113, 114]:  # JUMP opcodes
                    jump_count += 1
                    
            return jump_count > len(bytecode) * 0.3
            
        except Exception:
            return False
            
    def _detect_dead_code(self, data: bytes) -> bool:
        """Detect dead code injection."""
        try:
            code_obj = marshal.loads(data[16:])
            bytecode = code_obj.co_code
            
            # Look for unreachable code patterns
            unreachable_count = 0
            for i in range(0, len(bytecode) - 2, 2):
                opcode = bytecode[i]
                if opcode == 110:  # JUMP_FORWARD
                    # Check if next instruction is unreachable
                    if i + 2 < len(bytecode):
                        unreachable_count += 1
                        
            return unreachable_count > len(bytecode) * 0.2
            
        except Exception:
            return False
            
    def _deobfuscate_bytecode(self, data: bytes, obfuscation_types: List[str]) -> bytes:
        """Apply deobfuscation techniques to bytecode."""
        deobfuscated_data = data
        
        for obfuscation_type in obfuscation_types:
            try:
                if obfuscation_type == 'nop_padding':
                    deobfuscated_data = self._remove_nop_padding(deobfuscated_data)
                elif obfuscation_type == 'opcode_shifting':
                    deobfuscated_data = self._fix_opcode_shifting(deobfuscated_data)
                elif obfuscation_type == 'string_encryption':
                    deobfuscated_data = self._decrypt_strings(deobfuscated_data)
                elif obfuscation_type == 'control_flow_obfuscation':
                    deobfuscated_data = self._simplify_control_flow(deobfuscated_data)
                elif obfuscation_type == 'dead_code_injection':
                    deobfuscated_data = self._remove_dead_code(deobfuscated_data)
                    
            except Exception as e:
                print(f"Error deobfuscating {obfuscation_type}: {e}")
                
        return deobfuscated_data
        
    def _remove_nop_padding(self, data: bytes) -> bytes:
        """Remove NOP instruction padding."""
        # Simple NOP removal - in practice, you'd need more sophisticated analysis
        return data.replace(b'\x09\x00', b'')
        
    def _fix_opcode_shifting(self, data: bytes) -> bytes:
        """Fix opcode shifting obfuscation."""
        try:
            # Try to reverse common opcode shifting patterns
            code_obj = marshal.loads(data[16:])
            bytecode = list(code_obj.co_code)
            
            # Apply XOR with common keys
            keys = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]
            
            for key in keys:
                test_bytecode = bytearray(bytecode)
                for i in range(0, len(test_bytecode), 2):
                    test_bytecode[i] ^= key
                    
                # Check if this produces valid opcodes
                valid_opcodes = 0
                for i in range(0, len(test_bytecode), 2):
                    opcode = test_bytecode[i]
                    if opcode <= 255:  # Valid opcode range
                        valid_opcodes += 1
                        
                if valid_opcodes > len(test_bytecode) * 0.8:
                    # Found the key, apply it
                    for i in range(0, len(bytecode), 2):
                        bytecode[i] ^= key
                    break
                    
            # Reconstruct the code object
            code_obj.co_code = bytes(bytecode)
            return data[:16] + marshal.dumps(code_obj)
            
        except Exception:
            return data
            
    def _decrypt_strings(self, data: bytes) -> bytes:
        """Attempt to decrypt encrypted strings."""
        # This is a simplified implementation
        # In practice, you'd need to analyze the specific encryption method used
        
        try:
            code_obj = marshal.loads(data[16:])
            
            # Look for string constants and try common decryption methods
            for i, const in enumerate(code_obj.co_consts):
                if isinstance(const, str):
                    # Try ROT13
                    if self._looks_like_rot13(const):
                        code_obj.co_consts[i] = const.translate(str.maketrans(
                            'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                            'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                        ))
                        
                    # Try XOR with common keys
                    for key in range(1, 256):
                        decrypted = ''.join(chr(ord(c) ^ key) for c in const)
                        if self._looks_like_plaintext(decrypted):
                            code_obj.co_consts[i] = decrypted
                            break
                            
            return data[:16] + marshal.dumps(code_obj)
            
        except Exception:
            return data
            
    def _looks_like_rot13(self, text: str) -> bool:
        """Check if text looks like ROT13 encoded."""
        # Simple heuristic
        return len(text) > 3 and not any(c.islower() for c in text)
        
    def _looks_like_plaintext(self, text: str) -> bool:
        """Check if text looks like plaintext."""
        # Simple heuristic
        return (len(text) > 3 and 
                any(c.isalpha() for c in text) and 
                any(c.isspace() for c in text))
                
    def _simplify_control_flow(self, data: bytes) -> bytes:
        """Simplify obfuscated control flow."""
        # This is a complex operation that would require detailed analysis
        # For now, return the original data
        return data
        
    def _remove_dead_code(self, data: bytes) -> bytes:
        """Remove dead code from bytecode."""
        # This is a complex operation that would require detailed analysis
        # For now, return the original data
        return data
        
    def _decompile_bytecode(self, data: bytes) -> Optional[str]:
        """Decompile bytecode using available decompilers."""
        # Try uncompyle6 first
        if 'uncompyle6' in self.decompilers:
            try:
                return self._decompile_with_uncompyle6(data)
            except Exception as e:
                print(f"uncompyle6 failed: {e}")
                
        # Try decompyle3
        if 'decompyle3' in self.decompilers:
            try:
                return self._decompile_with_decompyle3(data)
            except Exception as e:
                print(f"decompyle3 failed: {e}")
                
        # Try built-in decompiler
        try:
            return self._builtin_decompiler(data)
        except Exception as e:
            print(f"Built-in decompiler failed: {e}")
            
        return None
        
    def _decompile_with_uncompyle6(self, data: bytes) -> str:
        """Decompile using uncompyle6."""
        import uncompyle6
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.pyc', delete=False) as f:
            f.write(data)
            temp_file = f.name
            
        try:
            # Decompile
            output = []
            uncompyle6.decompile_file(temp_file, output)
            return '\n'.join(output)
        finally:
            os.unlink(temp_file)
            
    def _decompile_with_decompyle3(self, data: bytes) -> str:
        """Decompile using decompyle3."""
        import decompyle3
        
        # Create temporary file
        with tempfile.NamedTemporaryFile(suffix='.pyc', delete=False) as f:
            f.write(data)
            temp_file = f.name
            
        try:
            # Decompile
            output = []
            decompyle3.decompile_file(temp_file, output)
            return '\n'.join(output)
        finally:
            os.unlink(temp_file)
            
    def _builtin_decompiler(self, data: bytes) -> str:
        """Built-in decompiler using dis module."""
        try:
            # Parse the bytecode
            code_obj = marshal.loads(data[16:])  # Skip header
            
            # Use dis to get bytecode instructions
            instructions = []
            for instruction in dis.get_instructions(code_obj):
                instructions.append(f"{instruction.offset:4d} {instruction.opname:20s} {instruction.argrepr}")
                
            # Create a simple disassembly
            result = f"# Decompiled with built-in decompiler\n"
            result += f"# Function: {code_obj.co_name}\n"
            result += f"# Constants: {code_obj.co_consts}\n"
            result += f"# Names: {code_obj.co_names}\n"
            result += f"# Varnames: {code_obj.co_varnames}\n\n"
            
            result += "def disassembled_code():\n"
            for instruction in instructions:
                result += f"    # {instruction}\n"
                
            return result
            
        except Exception as e:
            return f"# Failed to decompile: {e}\n"
            
    def analyze_bytecode(self, pyc_file: Path) -> Dict:
        """Analyze bytecode file for obfuscation and structure."""
        try:
            with open(pyc_file, 'rb') as f:
                data = f.read()
                
            # Parse header
            magic = data[:4]
            timestamp = struct.unpack('<I', data[4:8])[0]
            size = struct.unpack('<I', data[8:12])[0]
            
            # Parse code object
            code_obj = marshal.loads(data[16:])
            
            analysis = {
                'file': str(pyc_file),
                'magic': magic.hex(),
                'timestamp': timestamp,
                'size': size,
                'code_name': code_obj.co_name,
                'arg_count': code_obj.co_argcount,
                'const_count': len(code_obj.co_consts),
                'name_count': len(code_obj.co_names),
                'var_count': len(code_obj.co_varnames),
                'free_count': len(code_obj.co_freevars),
                'cell_count': len(code_obj.co_cellvars),
                'instruction_count': len(code_obj.co_code) // 2,
                'obfuscation_detected': self._detect_obfuscation(data),
                'constants': code_obj.co_consts[:10],  # First 10 constants
                'names': code_obj.co_names[:10],  # First 10 names
                'varnames': code_obj.co_varnames[:10]  # First 10 varnames
            }
            
            return analysis
            
        except Exception as e:
            return {'error': str(e)} 