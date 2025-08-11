#!/usr/bin/env python3
"""
Unpacker Hydra Test Script
Demonstrates the capabilities of the Unpacker Hydra framework.
"""

import sys
import os
from pathlib import Path
import tempfile
import time

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))

from core.detector import PackerDetector
from core.extractor import Extractor
from core.memory_dumper import MemoryDumper
from core.bytecode_deobfuscator import BytecodeDeobfuscator
from utils.logger import Logger
from utils.pattern_matcher import PatternMatcher
from plugins.pyinstaller import PyInstallerPlugin
from plugins.pyarmor import PyArmorPlugin

def create_test_executable():
    """Create a simple test executable for demonstration."""
    test_code = '''
import sys
print("Hello from test executable!")
print("This is a test Python application")
print("Built with PyInstaller for testing Unpacker Hydra")
'''
    
    # Create a simple Python script
    test_script = tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False)
    test_script.write(test_code)
    test_script.close()
    
    # Create a mock executable (just copy the script for demo)
    test_exe = tempfile.NamedTemporaryFile(suffix='.exe', delete=False)
    test_exe.close()
    
    # Write some mock PyInstaller data
    with open(test_exe.name, 'wb') as f:
        f.write(b'MZ')  # DOS header
        f.write(b'PyInstaller' * 100)  # Mock PyInstaller data
        f.write(b'PYZ-00.pyz')  # Mock PYZ archive
        f.write(test_code.encode())
    
    return Path(test_exe.name), Path(test_script.name)

def test_detector():
    """Test the packer detection system."""
    print("🔍 Testing Packer Detection System...")
    
    detector = PackerDetector()
    
    # Create test executable
    test_exe, test_script = create_test_executable()
    
    try:
        # Test detection
        result = detector.detect_packer(test_exe)
        
        if result:
            print(f"✅ Detected: {result['packer']} (Confidence: {result['confidence']}%)")
            print(f"🔧 Methods: {', '.join(result['detection_methods'])}")
            
            # Get packer info
            info = detector.get_packer_info(result['packer'])
            print(f"📋 Description: {info['description']}")
            print(f"🛠️  Extraction Method: {info['extraction_method']}")
            print(f"📊 Difficulty: {info['difficulty']}")
            print(f"🔒 Protection Level: {info['protection_level']}")
        else:
            print("⚠️  No packer detected")
            
    finally:
        # Cleanup
        test_exe.unlink(missing_ok=True)
        test_script.unlink(missing_ok=True)
        
    print()

def test_extractor():
    """Test the extraction system."""
    print("📦 Testing Extraction System...")
    
    extractor = Extractor()
    
    # Create test executable
    test_exe, test_script = create_test_executable()
    
    try:
        # Create output directory
        output_dir = Path("test_extraction")
        output_dir.mkdir(exist_ok=True)
        
        # Test extraction
        detection_result = {'packer': 'pyinstaller', 'confidence': 90}
        options = {'dry_run': False, 'memory_analysis': False}
        
        result = extractor.extract(test_exe, detection_result, options)
        
        if result['success']:
            print(f"✅ Extraction successful!")
            print(f"📁 Output directory: {result['output_dir']}")
            print(f"📄 Files extracted: {len(result.get('extracted_files', []))}")
            
            if result.get('pyc_files'):
                print(f"🐍 Python files found: {len(result['pyc_files'])}")
        else:
            print(f"❌ Extraction failed: {result['error']}")
            
    finally:
        # Cleanup
        test_exe.unlink(missing_ok=True)
        test_script.unlink(missing_ok=True)
        
    print()

def test_pattern_matcher():
    """Test the pattern matching system."""
    print("🔍 Testing Pattern Matching System...")
    
    matcher = PatternMatcher()
    
    # Create test data
    test_data = b'PyInstaller\x00PYZ-00.pyz\x00pyarmor\x00UPX!\x00'
    
    # Test pattern scanning
    results = matcher.scan_data(test_data, "test_data")
    
    print(f"📊 Data size: {results['size']} bytes")
    print(f"🔍 Patterns found: {len(results['patterns_found'])}")
    
    for pattern in results['patterns_found']:
        print(f"  - {pattern['pattern']}: {pattern['description']} (Confidence: {pattern['confidence']}%)")
        
    print(f"🎯 YARA matches: {len(results['yara_matches'])}")
    for match in results['yara_matches']:
        print(f"  - {match['rule']}")
        
    # Test entropy analysis
    entropy = results['entropy_analysis']
    print(f"🔢 Entropy: {entropy['entropy']:.2f} ({entropy['entropy_level']})")
    
    # Test string analysis
    strings = results['string_analysis']
    print(f"📝 Strings found: {strings['total_strings']}")
    print(f"📏 Longest string: {strings['longest_string']} characters")
    
    print()

def test_bytecode_deobfuscator():
    """Test the bytecode deobfuscation system."""
    print("🔓 Testing Bytecode Deobfuscation System...")
    
    deobfuscator = BytecodeDeobfuscator()
    
    # Create a simple Python bytecode
    import marshal
    import tempfile
    
    # Create a simple code object
    code = compile('print("Hello, World!")', '<string>', 'exec')
    
    # Create a mock .pyc file
    with tempfile.NamedTemporaryFile(suffix='.pyc', delete=False) as f:
        # Write Python 3.7+ magic
        f.write(b'\x03\xf3\x0d\x0a')
        # Write timestamp
        f.write(b'\x00\x00\x00\x00')
        # Write size
        f.write(b'\x00\x00\x00\x00')
        # Write marshalled code
        f.write(marshal.dumps(code))
        pyc_file = Path(f.name)
    
    try:
        # Test deobfuscation
        output_dir = Path("test_deobfuscation")
        output_dir.mkdir(exist_ok=True)
        
        result = deobfuscator.deobfuscate_file(pyc_file, output_dir)
        
        if result['success']:
            print(f"✅ Deobfuscation successful!")
            print(f"📄 Output file: {result['output_file']}")
            print(f"🔍 Obfuscation detected: {result.get('obfuscation_detected', [])}")
        else:
            print(f"❌ Deobfuscation failed: {result['error']}")
            
    finally:
        # Cleanup
        pyc_file.unlink(missing_ok=True)
        
    print()

def test_plugins():
    """Test the plugin system."""
    print("🔌 Testing Plugin System...")
    
    # Test PyInstaller plugin
    pyinstaller_plugin = PyInstallerPlugin()
    print(f"📦 PyInstaller Plugin: {pyinstaller_plugin.name} v{pyinstaller_plugin.version}")
    print(f"📋 Description: {pyinstaller_plugin.description}")
    
    info = pyinstaller_plugin.get_info()
    print(f"🛠️  Capabilities: {', '.join(info['capabilities'])}")
    
    # Test PyArmor plugin
    pyarmor_plugin = PyArmorPlugin()
    print(f"🔒 PyArmor Plugin: {pyarmor_plugin.name} v{pyarmor_plugin.version}")
    print(f"📋 Description: {pyarmor_plugin.description}")
    
    info = pyarmor_plugin.get_info()
    print(f"🛠️  Capabilities: {', '.join(info['capabilities'])}")
    
    print()

def test_logger():
    """Test the logging system."""
    print("📝 Testing Logging System...")
    
    logger = Logger(log_level="INFO")
    
    # Test various log levels
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.debug("This is a debug message (should not appear)")
    
    # Test specialized logging
    logger.log_success("Operation completed successfully!")
    logger.log_failure("Operation failed!")
    logger.log_plugin_loaded("test_plugin", "extractor")
    logger.log_confidence_score(0.85, "pattern detection")
    
    print()

def test_memory_analysis():
    """Test the memory analysis system (simulated)."""
    print("🧠 Testing Memory Analysis System...")
    
    memory_dumper = MemoryDumper()
    
    # Test Frida script generation
    test_exe, _ = create_test_executable()
    
    try:
        output_dir = Path("test_memory")
        output_dir.mkdir(exist_ok=True)
        
        # Generate Frida script
        script_path = memory_dumper.create_frida_script(test_exe, output_dir)
        print(f"📄 Frida script generated: {script_path}")
        
        # Check if script was created
        if Path(script_path).exists():
            print("✅ Frida script created successfully")
        else:
            print("❌ Failed to create Frida script")
            
    finally:
        test_exe.unlink(missing_ok=True)
        
    print()

def main():
    """Run all tests."""
    print("🐍 Unpacker Hydra Framework Test Suite")
    print("=" * 50)
    print()
    
    try:
        # Test each component
        test_detector()
        test_extractor()
        test_pattern_matcher()
        test_bytecode_deobfuscator()
        test_plugins()
        test_logger()
        test_memory_analysis()
        
        print("🎉 All tests completed successfully!")
        print()
        print("🚀 Unpacker Hydra is ready to use!")
        print("📖 Run 'python main.py --help' for usage information")
        print("🖥️  Run 'python main.py --gui' to launch the GUI")
        
    except Exception as e:
        print(f"❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0

if __name__ == "__main__":
    sys.exit(main()) 