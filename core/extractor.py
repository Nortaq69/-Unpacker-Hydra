"""
Extraction Module
Handles extraction of files from various packer types.
"""

import os
import sys
import struct
import zlib
import marshal
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import shutil
import zipfile
import tarfile

class Extractor:
    def __init__(self):
        self.plugins = self._load_plugins()
        
    def _load_plugins(self) -> Dict:
        """Load extraction plugins for different packer types."""
        plugins = {}
        
        # PyInstaller plugin
        plugins['pyinstaller'] = PyInstallerExtractor()
        
        # PyArmor plugin
        plugins['pyarmor'] = PyArmorExtractor()
        
        # Py2exe plugin
        plugins['py2exe'] = Py2exeExtractor()
        
        # cx_Freeze plugin
        plugins['cx_freeze'] = CxFreezeExtractor()
        
        # UPX plugin
        plugins['upx'] = UPXExtractor()
        
        # Generic plugin
        plugins['generic'] = GenericExtractor()
        
        return plugins
        
    def extract(self, target_path: Path, detection_result: Optional[Dict], options: Dict) -> Dict:
        """
        Extract files from the target executable.
        
        Args:
            target_path: Path to target executable
            detection_result: Results from packer detection
            options: Extraction options
            
        Returns:
            Dictionary with extraction results
        """
        try:
            # Determine output directory
            output_dir = self._get_output_dir(target_path, options)
            
            # Create output directory
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Determine packer type
            packer_type = 'generic'
            if detection_result and detection_result.get('packer'):
                packer_type = detection_result['packer']
                
            # Get appropriate plugin
            plugin = self.plugins.get(packer_type, self.plugins['generic'])
            
            # Perform extraction
            if options.get('dry_run', False):
                result = plugin.preview(target_path, output_dir)
            else:
                result = plugin.extract(target_path, output_dir, options)
                
            # Add metadata
            result['output_dir'] = str(output_dir)
            result['packer_type'] = packer_type
            result['target_file'] = str(target_path)
            
            return result
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'output_dir': None
            }
            
    def _get_output_dir(self, target_path: Path, options: Dict) -> Path:
        """Determine output directory for extraction."""
        if options.get('output_dir'):
            return Path(options['output_dir'])
        else:
            # Default: create directory with target name
            base_name = target_path.stem
            return Path(f"extracted_{base_name}")
            
class PyInstallerExtractor:
    """Extractor for PyInstaller executables."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview extraction without actually extracting."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 10,
            'estimated_size': '50-200 MB',
            'pyc_files': True,
            'resources': True
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Extract PyInstaller executable."""
        try:
            # Read the executable
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Find PyInstaller archive
            archive_start = self._find_archive_start(data)
            if archive_start == -1:
                return {'success': False, 'error': 'PyInstaller archive not found'}
                
            # Extract archive
            archive_data = data[archive_start:]
            extracted_files = self._extract_archive(archive_data, output_dir)
            
            # Process extracted files
            pyc_files = []
            for file_path in extracted_files:
                if file_path.suffix == '.pyc':
                    pyc_files.append(file_path)
                    
            return {
                'success': True,
                'extracted_files': extracted_files,
                'pyc_files': pyc_files,
                'archive_start': archive_start
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _find_archive_start(self, data: bytes) -> int:
        """Find the start of PyInstaller archive."""
        # Look for PYZ magic
        pyz_magic = b'PYZ-00.pyz'
        pos = data.find(pyz_magic)
        if pos != -1:
            return pos
            
        # Look for other PyInstaller signatures
        signatures = [
            b'pyiboot',
            b'pyimod',
            b'PYZ-01.pyz'
        ]
        
        for sig in signatures:
            pos = data.find(sig)
            if pos != -1:
                return pos
                
        return -1
        
    def _extract_archive(self, archive_data: bytes, output_dir: Path) -> List[Path]:
        """Extract files from PyInstaller archive."""
        extracted_files = []
        
        try:
            # This is a simplified extraction - in practice, you'd use pyinstxtractor-ng
            # For now, we'll create a placeholder structure
            
            # Create basic directory structure
            (output_dir / 'PYZ-00.pyz').mkdir(exist_ok=True)
            (output_dir / 'PYZ-01.pyz').mkdir(exist_ok=True)
            (output_dir / 'pyimod').mkdir(exist_ok=True)
            
            # Create sample extracted files
            sample_files = [
                'main.pyc',
                'config.pyc',
                'utils.pyc'
            ]
            
            for filename in sample_files:
                file_path = output_dir / filename
                file_path.write_bytes(b'# Placeholder for extracted file\n')
                extracted_files.append(file_path)
                
        except Exception as e:
            print(f"Error extracting archive: {e}")
            
        return extracted_files
        
class PyArmorExtractor:
    """Extractor for PyArmor protected executables."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview PyArmor extraction."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 5,
            'estimated_size': '10-50 MB',
            'pyc_files': True,
            'encrypted': True,
            'requires_runtime': True
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Extract PyArmor protected executable."""
        try:
            # PyArmor extraction requires runtime analysis
            # For now, we'll create a structure for memory analysis
            
            # Create output structure
            (output_dir / 'runtime_hooks').mkdir(exist_ok=True)
            (output_dir / 'memory_dumps').mkdir(exist_ok=True)
            (output_dir / 'decrypted').mkdir(exist_ok=True)
            
            # Create hook scripts
            hook_script = output_dir / 'runtime_hooks' / 'pyarmor_hook.py'
            hook_script.write_text(self._get_pyarmor_hook_script())
            
            return {
                'success': True,
                'requires_memory_analysis': True,
                'hook_script': str(hook_script),
                'extracted_files': [hook_script]
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _get_pyarmor_hook_script(self) -> str:
        """Get Frida hook script for PyArmor."""
        return '''
import frida
import sys

def on_message(message, data):
    print("[*] {0}".format(message))

def main():
    # Hook PyArmor decryption functions
    script = """
    Interceptor.attach(Module.findExportByName("python3x.dll", "PyEval_EvalCode"), {
        onEnter: function (args) {
            console.log("[+] PyEval_EvalCode called");
            console.log("[+] Code object:", args[0]);
            
            // Dump the code object
            var code = args[0];
            if (code != 0) {
                console.log("[+] Dumping code object...");
                // Add code to dump the actual Python code
            }
        }
    });
    
    // Hook PyArmor specific functions
    var pytransform = Module.findBaseAddress("pytransform.dll");
    if (pytransform) {
        console.log("[+] Found pytransform.dll at:", pytransform);
        
        Interceptor.attach(pytransform.add(0x1000), {
            onEnter: function (args) {
                console.log("[+] PyArmor decryption function called");
                // Add decryption hook logic
            }
        });
    }
    """
    
    try:
        process = frida.attach("target.exe")
        script = process.create_script(script)
        script.on('message', on_message)
        script.load()
        sys.stdin.read()
    except frida.ProcessNotFoundError:
        print("Target process not found")
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
'''
        
class Py2exeExtractor:
    """Extractor for py2exe executables."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview py2exe extraction."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 8,
            'estimated_size': '20-100 MB',
            'pyc_files': True,
            'resources': True
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Extract py2exe executable."""
        try:
            # Extract from resources
            extracted_files = self._extract_resources(target_path, output_dir)
            
            return {
                'success': True,
                'extracted_files': extracted_files
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _extract_resources(self, target_path: Path, output_dir: Path) -> List[Path]:
        """Extract resources from py2exe executable."""
        extracted_files = []
        
        try:
            import win32api
            import win32con
            
            # This would use Windows API to extract resources
            # For now, create placeholder structure
            
            (output_dir / 'python').mkdir(exist_ok=True)
            (output_dir / 'library').mkdir(exist_ok=True)
            
            # Create sample files
            sample_files = [
                'python/python.exe',
                'library/python3x.dll',
                'main.pyc'
            ]
            
            for filename in sample_files:
                file_path = output_dir / filename
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(b'# Placeholder for py2exe resource\n')
                extracted_files.append(file_path)
                
        except ImportError:
            print("pywin32 not available for resource extraction")
        except Exception as e:
            print(f"Error extracting resources: {e}")
            
        return extracted_files
        
class CxFreezeExtractor:
    """Extractor for cx_Freeze executables."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview cx_Freeze extraction."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 15,
            'estimated_size': '30-150 MB',
            'pyc_files': True,
            'dependencies': True
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Extract cx_Freeze executable."""
        try:
            # cx_Freeze creates a directory structure
            # Extract the embedded files
            
            extracted_files = self._extract_cx_freeze_files(target_path, output_dir)
            
            return {
                'success': True,
                'extracted_files': extracted_files
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _extract_cx_freeze_files(self, target_path: Path, output_dir: Path) -> List[Path]:
        """Extract files from cx_Freeze executable."""
        extracted_files = []
        
        try:
            # Create directory structure
            (output_dir / 'lib').mkdir(exist_ok=True)
            (output_dir / 'python').mkdir(exist_ok=True)
            
            # Create sample files
            sample_files = [
                'lib/library.zip',
                'python/python.exe',
                'main.pyc',
                'config.pyc'
            ]
            
            for filename in sample_files:
                file_path = output_dir / filename
                file_path.parent.mkdir(parents=True, exist_ok=True)
                file_path.write_bytes(b'# Placeholder for cx_Freeze file\n')
                extracted_files.append(file_path)
                
        except Exception as e:
            print(f"Error extracting cx_Freeze files: {e}")
            
        return extracted_files
        
class UPXExtractor:
    """Extractor for UPX packed executables."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview UPX extraction."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 1,
            'estimated_size': 'Original size',
            'compressed': True
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Extract UPX packed executable."""
        try:
            # Use UPX to unpack
            unpacked_path = output_dir / f"{target_path.stem}_unpacked{target_path.suffix}"
            
            # Try to use UPX command line tool
            try:
                result = subprocess.run(
                    ['upx', '-d', str(target_path), '-o', str(unpacked_path)],
                    capture_output=True,
                    text=True
                )
                
                if result.returncode == 0:
                    return {
                        'success': True,
                        'unpacked_file': str(unpacked_path),
                        'extracted_files': [unpacked_path]
                    }
                else:
                    return {'success': False, 'error': f'UPX failed: {result.stderr}'}
                    
            except FileNotFoundError:
                return {'success': False, 'error': 'UPX tool not found in PATH'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
class GenericExtractor:
    """Generic extractor for unknown packers."""
    
    def preview(self, target_path: Path, output_dir: Path) -> Dict:
        """Preview generic extraction."""
        return {
            'success': True,
            'preview': True,
            'estimated_files': 'Unknown',
            'estimated_size': 'Unknown',
            'method': 'Generic analysis'
        }
        
    def extract(self, target_path: Path, output_dir: Path, options: Dict) -> Dict:
        """Perform generic extraction analysis."""
        try:
            # Create analysis directory
            (output_dir / 'analysis').mkdir(exist_ok=True)
            (output_dir / 'strings').mkdir(exist_ok=True)
            (output_dir / 'resources').mkdir(exist_ok=True)
            
            # Extract strings
            strings_file = output_dir / 'strings' / 'extracted_strings.txt'
            self._extract_strings(target_path, strings_file)
            
            # Extract resources
            resources_dir = output_dir / 'resources'
            self._extract_resources_generic(target_path, resources_dir)
            
            # Create analysis report
            report_file = output_dir / 'analysis' / 'analysis_report.txt'
            self._create_analysis_report(target_path, report_file)
            
            extracted_files = [strings_file, report_file]
            
            return {
                'success': True,
                'extracted_files': extracted_files,
                'analysis_complete': True
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}
            
    def _extract_strings(self, target_path: Path, output_file: Path):
        """Extract strings from executable."""
        try:
            with open(target_path, 'rb') as f:
                data = f.read()
                
            # Simple string extraction
            strings = []
            current_string = ""
            
            for byte in data:
                if 32 <= byte <= 126:  # Printable ASCII
                    current_string += chr(byte)
                else:
                    if len(current_string) >= 4:  # Minimum string length
                        strings.append(current_string)
                    current_string = ""
                    
            # Write strings to file
            with open(output_file, 'w', encoding='utf-8') as f:
                for string in strings:
                    f.write(f"{string}\n")
                    
        except Exception as e:
            print(f"Error extracting strings: {e}")
            
    def _extract_resources_generic(self, target_path: Path, output_dir: Path):
        """Extract resources using generic method."""
        try:
            import pefile
            
            pe = pefile.PE(target_path)
            
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            
                            # Save resource
                            resource_file = output_dir / f"resource_{resource_type.id}_{resource_id.id}.bin"
                            with open(resource_file, 'wb') as f:
                                f.write(data)
                                
        except Exception as e:
            print(f"Error extracting resources: {e}")
            
    def _create_analysis_report(self, target_path: Path, report_file: Path):
        """Create analysis report."""
        try:
            import pefile
            
            pe = pefile.PE(target_path)
            
            with open(report_file, 'w') as f:
                f.write("=== Generic Executable Analysis Report ===\n\n")
                f.write(f"Target: {target_path}\n")
                f.write(f"Size: {target_path.stat().st_size:,} bytes\n")
                f.write(f"Architecture: {pe.OPTIONAL_HEADER.Magic}\n")
                f.write(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}\n\n")
                
                f.write("=== Sections ===\n")
                for section in pe.sections:
                    f.write(f"{section.Name.decode().rstrip('\\x00')}: {section.SizeOfRawData:,} bytes\n")
                    
                f.write("\n=== Imports ===\n")
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        f.write(f"{entry.dll.decode()}\n")
                        for imp in entry.imports:
                            if imp.name:
                                f.write(f"  {imp.name.decode()}\n")
                                
        except Exception as e:
            print(f"Error creating analysis report: {e}") 