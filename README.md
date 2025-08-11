# 🐍 Unpacker Hydra

**Advanced Python Executable Reverse Engineering Framework**

A comprehensive, cyberpunk-inspired tool for extracting and decompiling protected Python executables. Unpacker Hydra combines static analysis, dynamic memory dumping, and advanced deobfuscation techniques to reveal the source code hidden within protected Python applications.

![Unpacker Hydra Banner](https://img.shields.io/badge/Unpacker-Hydra-00ff00?style=for-the-badge&logo=python)
![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)

## 🚀 Features

### 🔍 **Advanced Packer Detection**
- **PyInstaller** - Complete archive extraction and analysis
- **PyArmor** - Runtime hooking and decryption capabilities
- **Py2exe** - Resource extraction and analysis
- **cx_Freeze** - Directory structure analysis
- **UPX** - Automatic unpacking
- **Themida** - Anti-debug bypass detection
- **VMProtect** - Virtual machine analysis

### 🧠 **Memory Analysis & Dumping**
- Real-time process monitoring
- Memory region scanning for Python objects
- YARA rule-based pattern detection
- Suspicious memory region identification
- Frida integration for advanced hooking

### 🔓 **Bytecode Deobfuscation**
- **uncompyle6** integration for Python 3.x
- **decompyle3** fallback support
- Built-in disassembly capabilities
- NOP padding detection and removal
- Opcode shifting analysis
- String encryption detection
- Control flow obfuscation analysis

### 🎨 **Cyberpunk GUI Interface**
- Dark theme with neon accents
- Real-time progress monitoring
- Multi-tab results display
- File tree visualization
- Memory analysis tables
- Comprehensive logging system

### 🔌 **Modular Plugin System**
- Hot-swappable extraction plugins
- Custom analysis pipelines
- Extensible detection signatures
- Plugin development framework

## 📋 Requirements

### System Requirements
- **OS**: Windows 10/11 (Primary), Linux/macOS (Experimental)
- **Python**: 3.8 or higher
- **RAM**: 4GB minimum, 8GB recommended
- **Storage**: 2GB free space

### Dependencies
```bash
# Core Analysis Libraries
capstone==4.0.2          # Disassembly engine
unicorn==2.0.1           # CPU emulation
pefile==2023.2.7         # PE file analysis
uncompyle6==3.9.0        # Python decompiler
frida==16.1.4            # Runtime instrumentation
yara-python==4.3.1       # Pattern matching
psutil==5.9.5            # Process monitoring

# GUI and Utilities
rich==13.5.2             # Terminal formatting
PyQt6==6.5.2             # GUI framework
lief==0.13.2             # Binary analysis
cryptography==41.0.4     # Cryptographic operations

# Optional Dependencies
pywin32==306             # Windows API (Windows only)
```

## 🛠️ Installation

### Quick Install
```bash
# Clone the repository
git clone https://github.com/your-username/UnpackerHydra.git
cd UnpackerHydra

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py --help
```

### Development Install
```bash
# Clone with submodules
git clone --recursive https://github.com/your-username/UnpackerHydra.git
cd UnpackerHydra

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/macOS
# or
venv\Scripts\activate     # Windows

# Install in development mode
pip install -e .
```

### Docker Install
```bash
# Build the Docker image
docker build -t unpacker-hydra .

# Run with GUI support (Windows)
docker run -it --rm -e DISPLAY=host.docker.internal:0.0 unpacker-hydra

# Run CLI only
docker run -it --rm unpacker-hydra python main.py target.exe
```

## 🎯 Usage

### Command Line Interface

#### Basic Analysis
```bash
# Analyze a target executable
python main.py target.exe

# With memory analysis
python main.py target.exe --memory

# Stealth mode (anti-detection)
python main.py target.exe --stealth

# Preview only (dry run)
python main.py target.exe --dry-run
```

#### Advanced Options
```bash
# Specify output directory
python main.py target.exe -o ./extracted_files

# Verbose output
python main.py target.exe -v

# Custom plugin directory
python main.py target.exe -p ./custom_plugins

# Memory analysis with custom interval
python main.py target.exe --memory --dump-interval 2.0
```

### Graphical User Interface

#### Launch GUI
```bash
# Launch the cyberpunk GUI
python main.py --gui
```

#### GUI Features
- **Target Selection**: Drag & drop or browse for executables
- **Analysis Options**: Configure memory analysis, stealth mode, etc.
- **Real-time Monitoring**: Live progress updates and status
- **Results Tabs**: 
  - **Log**: Real-time analysis log
  - **Results**: Summary of findings
  - **Files**: Extracted file tree
  - **Memory**: Memory analysis results
- **Export**: Save analysis reports in JSON or text format

### Plugin Development

#### Creating Custom Plugins
```python
# plugins/custom_packer.py
class CustomPackerPlugin:
    def __init__(self):
        self.name = "Custom Packer"
        self.version = "1.0.0"
        
    def can_handle(self, target_path):
        # Return True if this plugin can handle the target
        return True
        
    def extract(self, target_path, output_dir, options):
        # Implement extraction logic
        return {'success': True, 'files': []}
        
    def get_info(self):
        return {
            'name': self.name,
            'version': self.version,
            'capabilities': ['Custom extraction']
        }
```

## 📊 Analysis Pipeline

### Phase 1: Detection
1. **File Analysis**: PE header examination
2. **Signature Matching**: YARA rule application
3. **String Analysis**: Characteristic string detection
4. **Magic Byte Detection**: File format identification

### Phase 2: Extraction
1. **Packer-Specific Extraction**: Use appropriate plugin
2. **Archive Processing**: Extract embedded files
3. **Resource Extraction**: Extract PE resources
4. **File Organization**: Organize extracted content

### Phase 3: Memory Analysis (Optional)
1. **Process Launch**: Start target in controlled environment
2. **Memory Monitoring**: Real-time memory scanning
3. **Object Detection**: Find Python objects in memory
4. **Pattern Matching**: Apply YARA rules to memory

### Phase 4: Deobfuscation
1. **Bytecode Analysis**: Analyze Python bytecode
2. **Obfuscation Detection**: Identify protection techniques
3. **Deobfuscation**: Apply appropriate techniques
4. **Decompilation**: Convert to readable Python code

## 🔧 Configuration

### Configuration File
Create `config.yaml` in the project root:
```yaml
# Analysis Settings
analysis:
  memory_dump_interval: 1.0
  max_memory_dumps: 10
  stealth_mode: false
  verbose_output: true

# Plugin Settings
plugins:
  auto_load: true
  plugin_directory: "./plugins"
  enabled_plugins:
    - pyinstaller
    - pyarmor
    - py2exe

# GUI Settings
gui:
  theme: "cyberpunk"
  window_size: [1400, 900]
  auto_save_reports: true

# Logging Settings
logging:
  level: "INFO"
  file_output: true
  console_output: true
```

### Environment Variables
```bash
# Set custom plugin directory
export UNPACKER_HYDRA_PLUGIN_DIR="/path/to/plugins"

# Enable debug mode
export UNPACKER_HYDRA_DEBUG=1

# Set custom output directory
export UNPACKER_HYDRA_OUTPUT_DIR="/path/to/output"
```

## 🎨 GUI Themes

### Available Themes
- **Cyberpunk** (Default): Dark theme with neon blue accents
- **Terminal**: Classic terminal green on black
- **Frost**: Ice blue and white theme
- **Synthwave**: Retro 80s aesthetic

### Custom Themes
Create custom themes by modifying the CSS in `gui/main_window.py`:
```python
def get_custom_stylesheet():
    return """
    QMainWindow {
        background-color: #your-color;
        color: #your-text-color;
    }
    /* Add more custom styles */
    """
```

## 📈 Performance Optimization

### Memory Usage
- **Large Files**: Use `--chunk-size` for large executables
- **Memory Analysis**: Adjust `--dump-interval` for performance
- **Parallel Processing**: Enable multi-threading for batch analysis

### Speed Optimization
```bash
# Fast analysis (skip memory analysis)
python main.py target.exe --no-memory

# Parallel extraction
python main.py target.exe --parallel

# Cache results
python main.py target.exe --cache-results
```

## 🔒 Security Considerations

### Safe Analysis
- **Sandboxed Execution**: Target processes run in controlled environment
- **Non-Destructive**: Analysis doesn't modify original files
- **Permission Checks**: Validates file access permissions
- **Resource Limits**: Prevents excessive resource usage

### Anti-Detection
- **Stealth Mode**: Minimizes detection by target
- **Process Hiding**: Conceals analysis tools
- **Memory Protection**: Protects against anti-debug techniques

## 🐛 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Reinstall dependencies
pip install --force-reinstall -r requirements.txt

# Check Python version
python --version  # Should be 3.8+
```

#### GUI Issues
```bash
# Install PyQt6 dependencies
pip install PyQt6 PyQt6-Qt6 PyQt6-sip

# Run in headless mode
python main.py target.exe --no-gui
```

#### Memory Analysis Failures
```bash
# Run as administrator (Windows)
# Check process permissions
# Disable antivirus temporarily
```

#### Plugin Loading Errors
```bash
# Check plugin directory
ls plugins/

# Verify plugin syntax
python -m py_compile plugins/your_plugin.py
```

### Debug Mode
```bash
# Enable debug output
python main.py target.exe --debug

# Verbose logging
python main.py target.exe -v --log-level DEBUG
```

## 🤝 Contributing

### Development Setup
```bash
# Fork and clone
git clone https://github.com/your-username/UnpackerHydra.git
cd UnpackerHydra

# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Code formatting
black .
isort .

# Type checking
mypy .
```

### Contributing Guidelines
1. **Fork** the repository
2. **Create** a feature branch
3. **Implement** your changes
4. **Add** tests for new functionality
5. **Update** documentation
6. **Submit** a pull request

### Code Style
- **Python**: Follow PEP 8 guidelines
- **Documentation**: Use Google-style docstrings
- **Type Hints**: Include type annotations
- **Tests**: Maintain >90% code coverage

## 📚 Documentation

### API Reference
- [Core Modules](docs/api/core.md)
- [Plugin System](docs/api/plugins.md)
- [GUI Components](docs/api/gui.md)
- [Utilities](docs/api/utils.md)

### Tutorials
- [Getting Started](docs/tutorials/getting-started.md)
- [Plugin Development](docs/tutorials/plugin-development.md)
- [Advanced Analysis](docs/tutorials/advanced-analysis.md)
- [Custom Themes](docs/tutorials/custom-themes.md)

### Examples
- [Basic Usage](examples/basic_usage.py)
- [Custom Plugin](examples/custom_plugin.py)
- [Batch Analysis](examples/batch_analysis.py)
- [Integration](examples/integration.py)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **PyInstaller Team** - For the excellent packaging tool
- **Frida Team** - For the powerful instrumentation framework
- **YARA Team** - For the pattern matching engine
- **Capstone Team** - For the disassembly engine
- **Rich Team** - For the beautiful terminal formatting

## 📞 Support

### Getting Help
- **Issues**: [GitHub Issues](https://github.com/your-username/UnpackerHydra/issues)
- **Discussions**: [GitHub Discussions](https://github.com/your-username/UnpackerHydra/discussions)
- **Wiki**: [Project Wiki](https://github.com/your-username/UnpackerHydra/wiki)

### Community
- **Discord**: [Join our Discord](https://discord.gg/unpackerhydra)
- **Reddit**: [r/UnpackerHydra](https://reddit.com/r/UnpackerHydra)
- **Twitter**: [@UnpackerHydra](https://twitter.com/UnpackerHydra)

---

**⚡ Unpacker Hydra - Where Python Protection Meets Its Match**

*Built with ❤️ by the reverse engineering community* 