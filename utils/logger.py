"""
Logging Utility Module
Provides comprehensive logging functionality for Unpacker Hydra.
"""

import logging
import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
import json
from rich.logging import RichHandler
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

class Logger:
    def __init__(self, log_level: str = "INFO", log_file: Optional[str] = None):
        self.console = Console()
        self.log_level = getattr(logging, log_level.upper())
        self.log_file = log_file
        
        # Configure logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Setup logging configuration."""
        # Create formatter
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        # Setup root logger
        self.logger = logging.getLogger('UnpackerHydra')
        self.logger.setLevel(self.log_level)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Console handler with Rich formatting
        console_handler = RichHandler(
            console=self.console,
            show_time=True,
            show_path=False,
            markup=True
        )
        console_handler.setLevel(self.log_level)
        self.logger.addHandler(console_handler)
        
        # File handler if specified
        if self.log_file:
            file_handler = logging.FileHandler(self.log_file, encoding='utf-8')
            file_handler.setFormatter(formatter)
            file_handler.setLevel(self.log_level)
            self.logger.addHandler(file_handler)
            
    def info(self, message: str, **kwargs):
        """Log info message."""
        self.logger.info(message, **kwargs)
        
    def warning(self, message: str, **kwargs):
        """Log warning message."""
        self.logger.warning(message, **kwargs)
        
    def error(self, message: str, **kwargs):
        """Log error message."""
        self.logger.error(message, **kwargs)
        
    def debug(self, message: str, **kwargs):
        """Log debug message."""
        self.logger.debug(message, **kwargs)
        
    def critical(self, message: str, **kwargs):
        """Log critical message."""
        self.logger.critical(message, **kwargs)
        
    def log_analysis_start(self, target_file: str, options: Dict[str, Any]):
        """Log the start of an analysis session."""
        self.info("=" * 60)
        self.info("🧠 UNPACKER HYDRA ANALYSIS SESSION STARTED")
        self.info("=" * 60)
        self.info(f"🎯 Target: {target_file}")
        self.info(f"📊 Options: {json.dumps(options, indent=2)}")
        self.info(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.info("=" * 60)
        
    def log_analysis_complete(self, results: Dict[str, Any]):
        """Log the completion of an analysis session."""
        self.info("=" * 60)
        self.info("✅ UNPACKER HYDRA ANALYSIS SESSION COMPLETED")
        self.info("=" * 60)
        self.info(f"📈 Results: {json.dumps(results, indent=2)}")
        self.info(f"⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self.info("=" * 60)
        
    def log_packer_detection(self, detection_result: Dict[str, Any]):
        """Log packer detection results."""
        if detection_result:
            self.info(f"🔍 Packer Detected: {detection_result['packer']}")
            self.info(f"📊 Confidence: {detection_result['confidence']}%")
            self.info(f"🔧 Methods: {', '.join(detection_result['detection_methods'])}")
        else:
            self.info("🔍 No known packer detected - using generic analysis")
            
    def log_extraction_progress(self, stage: str, details: str = ""):
        """Log extraction progress."""
        self.info(f"📦 Extraction Stage: {stage}")
        if details:
            self.info(f"   Details: {details}")
            
    def log_memory_analysis(self, memory_result: Dict[str, Any]):
        """Log memory analysis results."""
        self.info("🧠 Memory Analysis Results:")
        self.info(f"   📊 Dumps Created: {memory_result.get('dumps_created', 0)}")
        self.info(f"   🐍 Python Objects: {len(memory_result.get('analysis_results', {}).get('python_objects', []))}")
        self.info(f"   🔓 Decrypted Patterns: {len(memory_result.get('analysis_results', {}).get('decrypted_code', []))}")
        self.info(f"   ⚠️  Suspicious Regions: {len(memory_result.get('analysis_results', {}).get('suspicious_regions', []))}")
        
    def log_deobfuscation_results(self, deobfuscation_result: Dict[str, Any]):
        """Log deobfuscation results."""
        self.info("🔓 Deobfuscation Results:")
        self.info(f"   ✅ Successfully Decompiled: {deobfuscation_result.get('decompiled_count', 0)}")
        self.info(f"   ❌ Failed: {deobfuscation_result.get('failed_count', 0)}")
        
        if deobfuscation_result.get('errors'):
            self.warning("   ⚠️  Errors encountered:")
            for error in deobfuscation_result['errors']:
                self.warning(f"      - {error}")
                
    def log_error(self, error: str, context: str = ""):
        """Log error with context."""
        self.error(f"💥 Error in {context}: {error}" if context else f"💥 Error: {error}")
        
    def log_warning(self, warning: str, context: str = ""):
        """Log warning with context."""
        self.warning(f"⚠️  Warning in {context}: {warning}" if context else f"⚠️  Warning: {warning}")
        
    def log_success(self, message: str):
        """Log success message."""
        self.info(f"✅ {message}")
        
    def log_failure(self, message: str):
        """Log failure message."""
        self.error(f"❌ {message}")
        
    def log_plugin_loaded(self, plugin_name: str, plugin_type: str):
        """Log plugin loading."""
        self.info(f"🔌 Loaded {plugin_type} plugin: {plugin_name}")
        
    def log_plugin_failed(self, plugin_name: str, error: str):
        """Log plugin loading failure."""
        self.warning(f"🔌 Failed to load plugin {plugin_name}: {error}")
        
    def create_analysis_report(self, analysis_data: Dict[str, Any], output_file: Path):
        """Create a comprehensive analysis report."""
        try:
            report = {
                'analysis_info': {
                    'tool': 'Unpacker Hydra',
                    'version': '1.0.0',
                    'timestamp': datetime.now().isoformat(),
                    'target_file': analysis_data.get('target_file', 'Unknown'),
                    'analysis_duration': analysis_data.get('duration', 'Unknown')
                },
                'detection_results': analysis_data.get('detection_results', {}),
                'extraction_results': analysis_data.get('extraction_results', {}),
                'memory_analysis': analysis_data.get('memory_analysis', {}),
                'deobfuscation_results': analysis_data.get('deobfuscation_results', {}),
                'summary': {
                    'success': analysis_data.get('success', False),
                    'files_extracted': len(analysis_data.get('extraction_results', {}).get('extracted_files', [])),
                    'pyc_files_found': len(analysis_data.get('extraction_results', {}).get('pyc_files', [])),
                    'decompiled_files': analysis_data.get('deobfuscation_results', {}).get('decompiled_count', 0)
                }
            }
            
            # Write JSON report
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
                
            self.info(f"📄 Analysis report saved to: {output_file}")
            
        except Exception as e:
            self.error(f"Failed to create analysis report: {e}")
            
    def log_performance_metrics(self, metrics: Dict[str, Any]):
        """Log performance metrics."""
        self.info("📊 Performance Metrics:")
        for metric, value in metrics.items():
            if isinstance(value, float):
                self.info(f"   {metric}: {value:.2f}")
            else:
                self.info(f"   {metric}: {value}")
                
    def log_security_scan(self, security_results: Dict[str, Any]):
        """Log security scan results."""
        self.info("🔒 Security Scan Results:")
        
        if security_results.get('suspicious_imports'):
            self.warning(f"   ⚠️  Suspicious Imports: {len(security_results['suspicious_imports'])}")
            for imp in security_results['suspicious_imports']:
                self.warning(f"      - {imp}")
                
        if security_results.get('anti_debug_detected'):
            self.warning("   ⚠️  Anti-debug techniques detected")
            
        if security_results.get('packing_detected'):
            self.info(f"   📦 Packing detected: {security_results['packing_detected']}")
            
        if security_results.get('encryption_detected'):
            self.info(f"   🔐 Encryption detected: {security_results['encryption_detected']}")
            
    def log_file_operations(self, operation: str, file_path: str, success: bool, details: str = ""):
        """Log file operations."""
        status = "✅" if success else "❌"
        self.info(f"{status} {operation}: {file_path}")
        if details:
            self.info(f"   Details: {details}")
            
    def log_network_activity(self, activity: str, target: str, success: bool):
        """Log network activity."""
        status = "✅" if success else "❌"
        self.info(f"{status} Network {activity}: {target}")
        
    def log_system_info(self):
        """Log system information."""
        import platform
        import psutil
        
        self.info("💻 System Information:")
        self.info(f"   OS: {platform.system()} {platform.release()}")
        self.info(f"   Architecture: {platform.machine()}")
        self.info(f"   Python: {platform.python_version()}")
        self.info(f"   CPU Cores: {psutil.cpu_count()}")
        self.info(f"   Memory: {psutil.virtual_memory().total // (1024**3)} GB")
        
    def create_session_log(self, session_id: str, output_dir: Path):
        """Create a session log file."""
        log_file = output_dir / f"session_{session_id}.log"
        
        # Create file handler for this session
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        file_handler.setLevel(self.log_level)
        
        # Add to logger
        self.logger.addHandler(file_handler)
        
        self.info(f"📝 Session log created: {log_file}")
        return log_file
        
    def log_plugin_execution(self, plugin_name: str, execution_time: float, success: bool):
        """Log plugin execution details."""
        status = "✅" if success else "❌"
        self.info(f"{status} Plugin {plugin_name} executed in {execution_time:.2f}s")
        
    def log_memory_usage(self):
        """Log current memory usage."""
        import psutil
        process = psutil.Process()
        memory_info = process.memory_info()
        
        self.debug(f"Memory Usage: {memory_info.rss // 1024 // 1024} MB")
        
    def log_disk_usage(self, path: str):
        """Log disk usage for a path."""
        import shutil
        
        try:
            total, used, free = shutil.disk_usage(path)
            self.debug(f"Disk Usage for {path}: {used // 1024 // 1024 // 1024} GB used, {free // 1024 // 1024 // 1024} GB free")
        except Exception as e:
            self.warning(f"Could not get disk usage for {path}: {e}")
            
    def log_exception(self, exception: Exception, context: str = ""):
        """Log exception with full traceback."""
        import traceback
        
        self.error(f"Exception in {context}: {str(exception)}" if context else f"Exception: {str(exception)}")
        self.debug(f"Traceback:\n{traceback.format_exc()}")
        
    def log_configuration(self, config: Dict[str, Any]):
        """Log configuration settings."""
        self.info("⚙️  Configuration:")
        for key, value in config.items():
            if isinstance(value, dict):
                self.info(f"   {key}:")
                for sub_key, sub_value in value.items():
                    self.info(f"     {sub_key}: {sub_value}")
            else:
                self.info(f"   {key}: {value}")
                
    def log_dependencies(self):
        """Log dependency information."""
        self.info("📦 Dependencies:")
        
        dependencies = [
            'capstone', 'unicorn', 'pefile', 'uncompyle6', 'frida',
            'yara-python', 'psutil', 'rich', 'PyQt6', 'lief',
            'cryptography', 'hexdump'
        ]
        
        for dep in dependencies:
            try:
                module = __import__(dep)
                version = getattr(module, '__version__', 'Unknown')
                self.info(f"   {dep}: {version}")
            except ImportError:
                self.warning(f"   {dep}: Not installed")
                
    def log_analysis_phase(self, phase: str, status: str = "started"):
        """Log analysis phase."""
        self.info(f"🔄 Phase: {phase} - {status}")
        
    def log_confidence_score(self, score: float, context: str = ""):
        """Log confidence score."""
        if score >= 0.8:
            self.info(f"🎯 High confidence ({score:.1%}) {context}")
        elif score >= 0.5:
            self.warning(f"⚠️  Medium confidence ({score:.1%}) {context}")
        else:
            self.warning(f"❓ Low confidence ({score:.1%}) {context}")
            
    def log_timing(self, operation: str, duration: float):
        """Log operation timing."""
        if duration < 1.0:
            self.debug(f"⏱️  {operation}: {duration*1000:.1f}ms")
        else:
            self.info(f"⏱️  {operation}: {duration:.2f}s")
            
    def log_file_size(self, file_path: str, size_bytes: int):
        """Log file size information."""
        if size_bytes < 1024:
            size_str = f"{size_bytes} B"
        elif size_bytes < 1024**2:
            size_str = f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            size_str = f"{size_bytes/1024**2:.1f} MB"
        else:
            size_str = f"{size_bytes/1024**3:.1f} GB"
            
        self.info(f"📁 {file_path}: {size_str}")
        
    def log_hash(self, file_path: str, hash_value: str, hash_type: str = "SHA256"):
        """Log file hash."""
        self.info(f"🔐 {hash_type} hash for {file_path}: {hash_value}")
        
    def log_entropy(self, file_path: str, entropy: float):
        """Log file entropy."""
        if entropy > 7.5:
            self.info(f"🔢 High entropy ({entropy:.2f}) for {file_path} - likely encrypted/compressed")
        elif entropy > 6.0:
            self.info(f"🔢 Medium entropy ({entropy:.2f}) for {file_path}")
        else:
            self.info(f"🔢 Low entropy ({entropy:.2f}) for {file_path} - likely plaintext") 