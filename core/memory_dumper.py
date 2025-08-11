"""
Memory Analysis and Dumping Module
Performs runtime analysis and memory dumping of protected executables.
"""

import os
import sys
import psutil
import subprocess
import tempfile
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import struct
import ctypes
from ctypes import wintypes
import yara

class MemoryDumper:
    def __init__(self):
        self.yara_rules = self._load_yara_rules()
        self.dump_interval = 1.0  # seconds
        self.max_dumps = 10
        
    def _load_yara_rules(self) -> List[yara.Rule]:
        """Load YARA rules for memory scanning."""
        rules = []
        
        # Python bytecode rule
        python_rule = """
        rule PythonBytecode {
            strings:
                $pyc_magic = { 03 F3 0D 0A }  // Python 3.x magic
                $pyc_magic_alt = { 03 F4 0D 0A }  // Alternative magic
                $pyc_magic_old = { 03 F2 0D 0A }  // Python 3.2 magic
            condition:
                any of them
        }
        """
        
        # PyArmor decrypted code rule
        pyarmor_rule = """
        rule PyArmorDecrypted {
            strings:
                $pyarmor_marker = "pyarmor" nocase
                $decrypted_marker = "decrypted" nocase
            condition:
                all of them
        }
        """
        
        # General code patterns
        code_pattern_rule = """
        rule CodePatterns {
            strings:
                $function_def = "def " ascii
                $class_def = "class " ascii
                $import_stmt = "import " ascii
                $from_import = "from " ascii
            condition:
                2 of them
        }
        """
        
        try:
            rules.append(yara.compile(source=python_rule))
            rules.append(yara.compile(source=pyarmor_rule))
            rules.append(yara.compile(source=code_pattern_rule))
        except Exception as e:
            print(f"Warning: Failed to compile YARA rules: {e}")
            
        return rules
        
    def analyze_memory(self, target_path: Path, extraction_result: Dict) -> Dict:
        """
        Perform memory analysis on the target executable.
        
        Args:
            target_path: Path to target executable
            extraction_result: Results from extraction phase
            
        Returns:
            Dictionary with memory analysis results
        """
        try:
            # Create memory analysis directory
            memory_dir = Path(extraction_result['output_dir']) / 'memory_analysis'
            memory_dir.mkdir(exist_ok=True)
            
            # Start the target process
            process_info = self._start_target_process(target_path)
            if not process_info:
                return {'success': False, 'error': 'Failed to start target process'}
                
            # Perform memory analysis
            analysis_result = self._perform_memory_analysis(
                process_info['pid'], 
                memory_dir, 
                extraction_result
            )
            
            # Clean up
            self._terminate_process(process_info['pid'])
            
            return analysis_result
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _start_target_process(self, target_path: Path) -> Optional[Dict]:
        """Start the target executable in a controlled environment."""
        try:
            # Create a sandboxed environment
            env = os.environ.copy()
            env['PYTHONPATH'] = ''  # Clear Python path
            
            # Start process with monitoring
            process = subprocess.Popen(
                [str(target_path)],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NEW_CONSOLE if os.name == 'nt' else 0
            )
            
            # Give it time to initialize
            time.sleep(2)
            
            return {
                'pid': process.pid,
                'process': process,
                'start_time': time.time()
            }
            
        except Exception as e:
            print(f"Error starting target process: {e}")
            return None
            
    def _perform_memory_analysis(self, pid: int, memory_dir: Path, extraction_result: Dict) -> Dict:
        """Perform comprehensive memory analysis."""
        try:
            analysis_results = {
                'memory_dumps': [],
                'python_objects': [],
                'decrypted_code': [],
                'suspicious_regions': [],
                'analysis_log': []
            }
            
            # Get process handle
            process = psutil.Process(pid)
            
            # Monitor memory for a period
            start_time = time.time()
            dump_count = 0
            
            while dump_count < self.max_dumps and time.time() - start_time < 30:
                try:
                    # Dump memory regions
                    dump_result = self._dump_memory_regions(process, memory_dir, dump_count)
                    if dump_result:
                        analysis_results['memory_dumps'].extend(dump_result)
                        
                    # Scan for Python objects
                    python_objects = self._scan_for_python_objects(process, memory_dir, dump_count)
                    analysis_results['python_objects'].extend(python_objects)
                    
                    # Look for decrypted code
                    decrypted_code = self._scan_for_decrypted_code(process, memory_dir, dump_count)
                    analysis_results['decrypted_code'].extend(decrypted_code)
                    
                    # Check for suspicious memory regions
                    suspicious = self._scan_suspicious_regions(process, memory_dir, dump_count)
                    analysis_results['suspicious_regions'].extend(suspicious)
                    
                    dump_count += 1
                    time.sleep(self.dump_interval)
                    
                except psutil.NoSuchProcess:
                    break
                except Exception as e:
                    analysis_results['analysis_log'].append(f"Error in dump {dump_count}: {e}")
                    
            # Create analysis report
            report_file = memory_dir / 'memory_analysis_report.txt'
            self._create_memory_analysis_report(analysis_results, report_file)
            
            return {
                'success': True,
                'analysis_results': analysis_results,
                'report_file': str(report_file),
                'dumps_created': dump_count
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _dump_memory_regions(self, process: psutil.Process, memory_dir: Path, dump_id: int) -> List[Dict]:
        """Dump memory regions from the process."""
        dumped_regions = []
        
        try:
            # Get memory maps
            memory_maps = process.memory_maps()
            
            for i, mmap in enumerate(memory_maps):
                try:
                    # Skip system DLLs and small regions
                    if (mmap.path and ('system32' in mmap.path.lower() or 
                                      'windows' in mmap.path.lower())):
                        continue
                        
                    if mmap.rss < 4096:  # Skip small regions
                        continue
                        
                    # Create dump file
                    dump_file = memory_dir / f"dump_{dump_id}_region_{i}.bin"
                    
                    # Read memory region
                    try:
                        with open(f"/proc/{process.pid}/mem", "rb") as mem_file:
                            mem_file.seek(mmap.addr)
                            data = mem_file.read(mmap.rss)
                            
                        # Write to file
                        with open(dump_file, "wb") as f:
                            f.write(data)
                            
                        dumped_regions.append({
                            'file': str(dump_file),
                            'address': hex(mmap.addr),
                            'size': mmap.rss,
                            'path': mmap.path or 'anonymous'
                        })
                        
                    except (PermissionError, OSError):
                        # Skip regions we can't read
                        continue
                        
                except Exception as e:
                    print(f"Error dumping region {i}: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error getting memory maps: {e}")
            
        return dumped_regions
        
    def _scan_for_python_objects(self, process: psutil.Process, memory_dir: Path, dump_id: int) -> List[Dict]:
        """Scan memory for Python objects and bytecode."""
        python_objects = []
        
        try:
            # Get memory maps
            memory_maps = process.memory_maps()
            
            for mmap in memory_maps:
                try:
                    # Read memory region
                    with open(f"/proc/{process.pid}/mem", "rb") as mem_file:
                        mem_file.seek(mmap.addr)
                        data = mem_file.read(min(mmap.rss, 1024*1024))  # Read up to 1MB
                        
                    # Scan for Python bytecode patterns
                    python_objects.extend(self._find_python_objects_in_data(data, mmap.addr))
                    
                except (PermissionError, OSError):
                    continue
                except Exception as e:
                    print(f"Error scanning region for Python objects: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error scanning for Python objects: {e}")
            
        return python_objects
        
    def _find_python_objects_in_data(self, data: bytes, base_addr: int) -> List[Dict]:
        """Find Python objects in memory data."""
        objects = []
        
        # Python bytecode magic numbers
        magic_numbers = [
            b'\x03\xf3\x0d\x0a',  # Python 3.7+
            b'\x03\xf4\x0d\x0a',  # Python 3.8+
            b'\x03\xf2\x0d\x0a',  # Python 3.2
        ]
        
        for magic in magic_numbers:
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos == -1:
                    break
                    
                # Try to parse as Python bytecode
                try:
                    # Read timestamp and size
                    if len(data) >= pos + 12:
                        timestamp = struct.unpack('<I', data[pos+4:pos+8])[0]
                        size = struct.unpack('<I', data[pos+8:pos+12])[0]
                        
                        if 0 < size < 1024*1024:  # Reasonable size
                            objects.append({
                                'address': hex(base_addr + pos),
                                'magic': magic.hex(),
                                'timestamp': timestamp,
                                'size': size,
                                'offset': pos
                            })
                            
                except Exception:
                    pass
                    
                offset = pos + 1
                
        return objects
        
    def _scan_for_decrypted_code(self, process: psutil.Process, memory_dir: Path, dump_id: int) -> List[Dict]:
        """Scan for decrypted code patterns."""
        decrypted_code = []
        
        try:
            # Get memory maps
            memory_maps = process.memory_maps()
            
            for mmap in memory_maps:
                try:
                    # Read memory region
                    with open(f"/proc/{process.pid}/mem", "rb") as mem_file:
                        mem_file.seek(mmap.addr)
                        data = mem_file.read(min(mmap.rss, 1024*1024))
                        
                    # Apply YARA rules
                    for rule in self.yara_rules:
                        matches = rule.match(data=data)
                        for match in matches:
                            decrypted_code.append({
                                'address': hex(base_addr + match.offset),
                                'rule': match.rule,
                                'strings': [str(s) for s in match.strings],
                                'region_path': mmap.path or 'anonymous'
                            })
                            
                except (PermissionError, OSError):
                    continue
                except Exception as e:
                    print(f"Error scanning for decrypted code: {e}")
                    continue
                    
        except Exception as e:
            print(f"Error scanning for decrypted code: {e}")
            
        return decrypted_code
        
    def _scan_suspicious_regions(self, process: psutil.Process, memory_dir: Path, dump_id: int) -> List[Dict]:
        """Scan for suspicious memory regions."""
        suspicious_regions = []
        
        try:
            # Get memory maps
            memory_maps = process.memory_maps()
            
            for mmap in memory_maps:
                suspicious_flags = []
                
                # Check for executable regions
                if 'x' in mmap.perms:
                    suspicious_flags.append('executable')
                    
                # Check for writable executable regions
                if 'w' in mmap.perms and 'x' in mmap.perms:
                    suspicious_flags.append('writable_executable')
                    
                # Check for large anonymous regions
                if not mmap.path and mmap.rss > 1024*1024:
                    suspicious_flags.append('large_anonymous')
                    
                # Check for suspicious names
                if mmap.path:
                    suspicious_names = ['pyarmor', 'themida', 'vmprotect', 'packed']
                    for name in suspicious_names:
                        if name in mmap.path.lower():
                            suspicious_flags.append(f'suspicious_name_{name}')
                            
                if suspicious_flags:
                    suspicious_regions.append({
                        'address': hex(mmap.addr),
                        'size': mmap.rss,
                        'permissions': mmap.perms,
                        'path': mmap.path or 'anonymous',
                        'flags': suspicious_flags
                    })
                    
        except Exception as e:
            print(f"Error scanning suspicious regions: {e}")
            
        return suspicious_regions
        
    def _create_memory_analysis_report(self, analysis_results: Dict, report_file: Path):
        """Create a comprehensive memory analysis report."""
        try:
            with open(report_file, 'w') as f:
                f.write("=== Memory Analysis Report ===\n\n")
                
                f.write(f"Memory Dumps Created: {len(analysis_results['memory_dumps'])}\n")
                f.write(f"Python Objects Found: {len(analysis_results['python_objects'])}\n")
                f.write(f"Decrypted Code Patterns: {len(analysis_results['decrypted_code'])}\n")
                f.write(f"Suspicious Regions: {len(analysis_results['suspicious_regions'])}\n\n")
                
                f.write("=== Python Objects ===\n")
                for obj in analysis_results['python_objects']:
                    f.write(f"Address: {obj['address']}, Magic: {obj['magic']}, Size: {obj['size']}\n")
                    
                f.write("\n=== Decrypted Code Patterns ===\n")
                for code in analysis_results['decrypted_code']:
                    f.write(f"Address: {code['address']}, Rule: {code['rule']}\n")
                    
                f.write("\n=== Suspicious Regions ===\n")
                for region in analysis_results['suspicious_regions']:
                    f.write(f"Address: {region['address']}, Flags: {', '.join(region['flags'])}\n")
                    
                f.write("\n=== Analysis Log ===\n")
                for log_entry in analysis_results['analysis_log']:
                    f.write(f"{log_entry}\n")
                    
        except Exception as e:
            print(f"Error creating memory analysis report: {e}")
            
    def _terminate_process(self, pid: int):
        """Safely terminate the target process."""
        try:
            process = psutil.Process(pid)
            process.terminate()
            
            # Wait for termination
            try:
                process.wait(timeout=5)
            except psutil.TimeoutExpired:
                process.kill()
                
        except psutil.NoSuchProcess:
            pass
        except Exception as e:
            print(f"Error terminating process: {e}")
            
    def create_frida_script(self, target_path: Path, output_dir: Path) -> str:
        """Create a Frida script for advanced memory analysis."""
        script_content = '''
import frida
import sys
import time

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    elif message['type'] == 'error':
        print("[!] {0}".format(message['stack']))

def main():
    # Advanced memory analysis script
    script = """
    var pythonDll = Module.findBaseAddress("python3x.dll");
    if (!pythonDll) {
        pythonDll = Module.findBaseAddress("python39.dll");
    }
    if (!pythonDll) {
        pythonDll = Module.findBaseAddress("python38.dll");
    }
    
    if (pythonDll) {
        console.log("[+] Found Python DLL at:", pythonDll);
        
        // Hook PyEval_EvalCode to capture code objects
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
        
        // Hook PyCode_New to capture new code objects
        var PyCode_New = Module.findExportByName("python3x.dll", "PyCode_New");
        if (PyCode_New) {
            Interceptor.attach(PyCode_New, {
                onLeave: function (retval) {
                    console.log("[+] New code object created:", retval);
                }
            });
        }
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
    
    // Scan for Python bytecode patterns in memory
    function scanForPythonCode() {
        var ranges = Process.enumerateRanges('r--');
        ranges.forEach(function (range) {
            if (range.size > 4096) {  // Skip small ranges
                try {
                    var data = Memory.readByteArray(range.base, Math.min(range.size, 1024*1024));
                    if (data) {
                        // Look for Python magic
                        var magic = [0x03, 0xf3, 0x0d, 0x0a];
                        for (var i = 0; i < data.length - 4; i++) {
                            if (data[i] == magic[0] && data[i+1] == magic[1] && 
                                data[i+2] == magic[2] && data[i+3] == magic[3]) {
                                console.log("[+] Found Python bytecode at:", range.base.add(i));
                            }
                        }
                    }
                } catch (e) {
                    // Skip unreadable ranges
                }
            }
        });
    }
    
    // Perform initial scan
    setTimeout(scanForPythonCode, 1000);
    """
    
    try:
        process = frida.attach("target.exe")
        script = process.create_script(script)
        script.on('message', on_message)
        script.load()
        
        print("[*] Frida script loaded. Press Enter to exit...")
        sys.stdin.read()
        
    except frida.ProcessNotFoundError:
        print("[!] Target process not found")
    except Exception as e:
        print("[!] Error:", e)

if __name__ == "__main__":
    main()
'''
        
        script_file = output_dir / 'frida_memory_analysis.py'
        script_file.write_text(script_content)
        return str(script_file) 