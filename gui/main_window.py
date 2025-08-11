"""
GUI Main Window Module
PyQt6-based GUI interface for Unpacker Hydra.
"""

import sys
import os
from pathlib import Path
from typing import Optional, Dict, Any
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QTextEdit, QFileDialog, QProgressBar,
    QTabWidget, QGroupBox, QCheckBox, QLineEdit, QComboBox,
    QTableWidget, QTableWidgetItem, QSplitter, QTreeWidget,
    QTreeWidgetItem, QMessageBox, QStatusBar, QMenuBar, QMenu,
    QAction, QDialog, QFormLayout, QSpinBox, QSlider
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation, QEasingCurve
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon, QPixmap, QPainter, QBrush
import json
import threading
import time

from core.detector import PackerDetector
from core.extractor import Extractor
from core.memory_dumper import MemoryDumper
from core.bytecode_deobfuscator import BytecodeDeobfuscator
from utils.logger import Logger

class AnalysisWorker(QThread):
    """Worker thread for analysis operations."""
    progress_updated = pyqtSignal(str)
    result_ready = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target_file: str, options: Dict[str, Any]):
        super().__init__()
        self.target_file = target_file
        self.options = options
        
    def run(self):
        """Run the analysis in a separate thread."""
        try:
            self.progress_updated.emit("Initializing analysis...")
            
            # Initialize components
            detector = PackerDetector()
            extractor = Extractor()
            memory_dumper = MemoryDumper()
            deobfuscator = BytecodeDeobfuscator()
            
            target_path = Path(self.target_file)
            
            # Phase 1: Detection
            self.progress_updated.emit("Detecting packer/protection...")
            detection_result = detector.detect_packer(target_path)
            
            # Phase 2: Extraction
            self.progress_updated.emit("Extracting files...")
            extraction_result = extractor.extract(target_path, detection_result, self.options)
            
            if not extraction_result['success']:
                self.error_occurred.emit(f"Extraction failed: {extraction_result['error']}")
                return
                
            # Phase 3: Memory Analysis (if enabled)
            memory_result = None
            if self.options.get('memory_analysis', False):
                self.progress_updated.emit("Performing memory analysis...")
                memory_result = memory_dumper.analyze_memory(target_path, extraction_result)
                
            # Phase 4: Deobfuscation
            deobfuscation_result = None
            if extraction_result.get('pyc_files'):
                self.progress_updated.emit("Deobfuscating bytecode...")
                deobfuscation_result = deobfuscator.deobfuscate_all(
                    extraction_result['pyc_files'],
                    Path(extraction_result['output_dir'])
                )
                
            # Compile results
            results = {
                'success': True,
                'detection_result': detection_result,
                'extraction_result': extraction_result,
                'memory_result': memory_result,
                'deobfuscation_result': deobfuscation_result
            }
            
            self.progress_updated.emit("Analysis complete!")
            self.result_ready.emit(results)
            
        except Exception as e:
            self.error_occurred.emit(str(e))

class CyberpunkStyle:
    """Cyberpunk styling for the GUI."""
    
    @staticmethod
    def get_dark_palette():
        """Get dark cyberpunk color palette."""
        palette = QPalette()
        
        # Dark background colors
        palette.setColor(QPalette.ColorRole.Window, QColor(20, 20, 25))
        palette.setColor(QPalette.ColorRole.WindowText, QColor(220, 220, 220))
        palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 35))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor(40, 40, 45))
        palette.setColor(QPalette.ColorRole.ToolTipBase, QColor(20, 20, 25))
        palette.setColor(QPalette.ColorRole.ToolTipText, QColor(220, 220, 220))
        palette.setColor(QPalette.ColorRole.Text, QColor(220, 220, 220))
        palette.setColor(QPalette.ColorRole.Button, QColor(50, 50, 55))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor(220, 220, 220))
        palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 255, 255))
        palette.setColor(QPalette.ColorRole.Link, QColor(0, 255, 255))
        palette.setColor(QPalette.ColorRole.Highlight, QColor(0, 150, 255))
        palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
        
        return palette
        
    @staticmethod
    def get_stylesheet():
        """Get cyberpunk stylesheet."""
        return """
        QMainWindow {
            background-color: #141419;
            color: #dcdcdc;
        }
        
        QWidget {
            background-color: #1e1e23;
            color: #dcdcdc;
            border: none;
        }
        
        QPushButton {
            background-color: #32323a;
            border: 2px solid #0096ff;
            border-radius: 5px;
            padding: 8px 16px;
            color: #ffffff;
            font-weight: bold;
            font-size: 12px;
        }
        
        QPushButton:hover {
            background-color: #0096ff;
            border-color: #00b4ff;
        }
        
        QPushButton:pressed {
            background-color: #007acc;
            border-color: #005a99;
        }
        
        QPushButton:disabled {
            background-color: #2a2a2a;
            border-color: #555555;
            color: #888888;
        }
        
        QTextEdit {
            background-color: #1a1a1f;
            border: 2px solid #0096ff;
            border-radius: 5px;
            padding: 8px;
            color: #00ff00;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 11px;
        }
        
        QLineEdit {
            background-color: #1a1a1f;
            border: 2px solid #0096ff;
            border-radius: 5px;
            padding: 8px;
            color: #ffffff;
            font-size: 12px;
        }
        
        QLineEdit:focus {
            border-color: #00b4ff;
        }
        
        QComboBox {
            background-color: #1a1a1f;
            border: 2px solid #0096ff;
            border-radius: 5px;
            padding: 8px;
            color: #ffffff;
            font-size: 12px;
        }
        
        QComboBox::drop-down {
            border: none;
        }
        
        QComboBox::down-arrow {
            image: none;
            border-left: 5px solid transparent;
            border-right: 5px solid transparent;
            border-top: 5px solid #0096ff;
        }
        
        QTabWidget::pane {
            border: 2px solid #0096ff;
            border-radius: 5px;
            background-color: #1e1e23;
        }
        
        QTabBar::tab {
            background-color: #32323a;
            border: 2px solid #0096ff;
            border-bottom: none;
            border-radius: 5px 5px 0px 0px;
            padding: 8px 16px;
            color: #ffffff;
            font-weight: bold;
        }
        
        QTabBar::tab:selected {
            background-color: #0096ff;
        }
        
        QTabBar::tab:hover {
            background-color: #00b4ff;
        }
        
        QGroupBox {
            font-weight: bold;
            border: 2px solid #0096ff;
            border-radius: 5px;
            margin-top: 10px;
            padding-top: 10px;
            color: #ffffff;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: #0096ff;
        }
        
        QProgressBar {
            border: 2px solid #0096ff;
            border-radius: 5px;
            text-align: center;
            background-color: #1a1a1f;
            color: #ffffff;
        }
        
        QProgressBar::chunk {
            background-color: #0096ff;
            border-radius: 3px;
        }
        
        QTableWidget {
            background-color: #1a1a1f;
            border: 2px solid #0096ff;
            border-radius: 5px;
            gridline-color: #0096ff;
            color: #ffffff;
        }
        
        QTableWidget::item {
            padding: 5px;
        }
        
        QTableWidget::item:selected {
            background-color: #0096ff;
        }
        
        QHeaderView::section {
            background-color: #32323a;
            border: 1px solid #0096ff;
            padding: 5px;
            color: #ffffff;
            font-weight: bold;
        }
        
        QTreeWidget {
            background-color: #1a1a1f;
            border: 2px solid #0096ff;
            border-radius: 5px;
            color: #ffffff;
        }
        
        QTreeWidget::item {
            padding: 5px;
        }
        
        QTreeWidget::item:selected {
            background-color: #0096ff;
        }
        
        QStatusBar {
            background-color: #32323a;
            color: #ffffff;
            border-top: 2px solid #0096ff;
        }
        
        QMenuBar {
            background-color: #32323a;
            color: #ffffff;
            border-bottom: 2px solid #0096ff;
        }
        
        QMenuBar::item {
            background-color: transparent;
            padding: 8px 12px;
        }
        
        QMenuBar::item:selected {
            background-color: #0096ff;
        }
        
        QMenu {
            background-color: #1e1e23;
            border: 2px solid #0096ff;
            color: #ffffff;
        }
        
        QMenu::item {
            padding: 8px 20px;
        }
        
        QMenu::item:selected {
            background-color: #0096ff;
        }
        
        QCheckBox {
            color: #ffffff;
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 18px;
            height: 18px;
            border: 2px solid #0096ff;
            border-radius: 3px;
            background-color: #1a1a1f;
        }
        
        QCheckBox::indicator:checked {
            background-color: #0096ff;
            image: url(data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMTIiIGhlaWdodD0iMTIiIHZpZXdCb3g9IjAgMCAxMiAxMiIgZmlsbD0ibm9uZSIgeG1sbnM9Imh0dHA6Ly93d3cudzMub3JnLzIwMDAvc3ZnIj4KPHBhdGggZD0iTTEwIDNMNC41IDguNUwyIDYiIHN0cm9rZT0id2hpdGUiIHN0cm9rZS13aWR0aD0iMiIgc3Ryb2tlLWxpbmVjYXA9InJvdW5kIiBzdHJva2UtbGluZWpvaW49InJvdW5kIi8+Cjwvc3ZnPgo=);
        }
        """

class UnpackerHydraGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.analysis_worker = None
        self.logger = Logger()
        self.init_ui()
        
    def init_ui(self):
        """Initialize the user interface."""
        self.setWindowTitle("Unpacker Hydra - Advanced Python Executable Reverse Engineering")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply cyberpunk styling
        self.setStyleSheet(CyberpunkStyle.get_stylesheet())
        self.setPalette(CyberpunkStyle.get_dark_palette())
        
        # Create central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Create main layout
        main_layout = QVBoxLayout(central_widget)
        
        # Create menu bar
        self.create_menu_bar()
        
        # Create main content
        self.create_main_content(main_layout)
        
        # Create status bar
        self.create_status_bar()
        
        # Set window icon (placeholder)
        self.setWindowIcon(self.create_icon())
        
    def create_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()
        
        # File menu
        file_menu = menubar.addMenu('File')
        
        open_action = QAction('Open Target', self)
        open_action.setShortcut('Ctrl+O')
        open_action.triggered.connect(self.open_target_file)
        file_menu.addAction(open_action)
        
        save_action = QAction('Save Report', self)
        save_action.setShortcut('Ctrl+S')
        save_action.triggered.connect(self.save_report)
        file_menu.addAction(save_action)
        
        file_menu.addSeparator()
        
        exit_action = QAction('Exit', self)
        exit_action.setShortcut('Ctrl+Q')
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Analysis menu
        analysis_menu = menubar.addMenu('Analysis')
        
        start_action = QAction('Start Analysis', self)
        start_action.setShortcut('F5')
        start_action.triggered.connect(self.start_analysis)
        analysis_menu.addAction(start_action)
        
        stop_action = QAction('Stop Analysis', self)
        stop_action.setShortcut('F6')
        stop_action.triggered.connect(self.stop_analysis)
        analysis_menu.addAction(stop_action)
        
        # Tools menu
        tools_menu = menubar.addMenu('Tools')
        
        settings_action = QAction('Settings', self)
        settings_action.triggered.connect(self.show_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = menubar.addMenu('Help')
        
        about_action = QAction('About', self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def create_main_content(self, main_layout):
        """Create the main content area."""
        # Create splitter for resizable panels
        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)
        
        # Left panel - Controls and options
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Results and logs
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([400, 1000])
        
    def create_left_panel(self):
        """Create the left control panel."""
        left_widget = QWidget()
        layout = QVBoxLayout(left_widget)
        
        # Target file selection
        target_group = QGroupBox("Target File")
        target_layout = QVBoxLayout(target_group)
        
        self.target_path_edit = QLineEdit()
        self.target_path_edit.setPlaceholderText("Select target executable...")
        target_layout.addWidget(self.target_path_edit)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_target_file)
        target_layout.addWidget(browse_button)
        
        layout.addWidget(target_group)
        
        # Analysis options
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout(options_group)
        
        self.memory_analysis_cb = QCheckBox("Memory Analysis")
        self.memory_analysis_cb.setChecked(True)
        options_layout.addWidget(self.memory_analysis_cb)
        
        self.stealth_mode_cb = QCheckBox("Stealth Mode")
        options_layout.addWidget(self.stealth_mode_cb)
        
        self.verbose_cb = QCheckBox("Verbose Output")
        options_layout.addWidget(self.verbose_cb)
        
        self.dry_run_cb = QCheckBox("Dry Run (Preview Only)")
        options_layout.addWidget(self.dry_run_cb)
        
        layout.addWidget(options_group)
        
        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QVBoxLayout(output_group)
        
        self.output_path_edit = QLineEdit()
        self.output_path_edit.setPlaceholderText("Auto-generated...")
        output_layout.addWidget(self.output_path_edit)
        
        output_browse_button = QPushButton("Browse...")
        output_browse_button.clicked.connect(self.browse_output_directory)
        output_layout.addWidget(output_browse_button)
        
        layout.addWidget(output_group)
        
        # Analysis controls
        controls_group = QGroupBox("Analysis Controls")
        controls_layout = QVBoxLayout(controls_group)
        
        self.start_button = QPushButton("Start Analysis")
        self.start_button.clicked.connect(self.start_analysis)
        controls_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Stop Analysis")
        self.stop_button.clicked.connect(self.stop_analysis)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.stop_button)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        controls_layout.addWidget(self.progress_bar)
        
        layout.addWidget(controls_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return left_widget
        
    def create_right_panel(self):
        """Create the right results panel."""
        right_widget = QWidget()
        layout = QVBoxLayout(right_widget)
        
        # Create tab widget
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Log tab
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.tab_widget.addTab(self.log_text, "Log")
        
        # Results tab
        self.results_text = QTextEdit()
        self.results_text.setReadOnly(True)
        self.tab_widget.addTab(self.results_text, "Results")
        
        # Files tab
        self.files_tree = QTreeWidget()
        self.files_tree.setHeaderLabels(["File", "Type", "Size"])
        self.tab_widget.addTab(self.files_tree, "Files")
        
        # Memory tab
        self.memory_table = QTableWidget()
        self.memory_table.setColumnCount(4)
        self.memory_table.setHorizontalHeaderLabels(["Address", "Size", "Type", "Status"])
        self.tab_widget.addTab(self.memory_table, "Memory")
        
        return right_widget
        
    def create_status_bar(self):
        """Create the status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Ready")
        
    def create_icon(self):
        """Create a placeholder icon."""
        # Create a simple icon with a "H" for Hydra
        pixmap = QPixmap(32, 32)
        pixmap.fill(QColor(0, 150, 255))
        
        painter = QPainter(pixmap)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Arial", 20, QFont.Weight.Bold))
        painter.drawText(pixmap.rect(), Qt.AlignmentFlag.AlignCenter, "H")
        painter.end()
        
        return QIcon(pixmap)
        
    def browse_target_file(self):
        """Browse for target file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Target Executable",
            "",
            "Executable Files (*.exe);;All Files (*.*)"
        )
        
        if file_path:
            self.target_path_edit.setText(file_path)
            
    def browse_output_directory(self):
        """Browse for output directory."""
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Select Output Directory"
        )
        
        if dir_path:
            self.output_path_edit.setText(dir_path)
            
    def start_analysis(self):
        """Start the analysis process."""
        target_file = self.target_path_edit.text()
        
        if not target_file:
            QMessageBox.warning(self, "Warning", "Please select a target file.")
            return
            
        if not os.path.exists(target_file):
            QMessageBox.warning(self, "Warning", "Target file does not exist.")
            return
            
        # Prepare options
        options = {
            'memory_analysis': self.memory_analysis_cb.isChecked(),
            'stealth_mode': self.stealth_mode_cb.isChecked(),
            'verbose': self.verbose_cb.isChecked(),
            'dry_run': self.dry_run_cb.isChecked(),
            'output_dir': self.output_path_edit.text() if self.output_path_edit.text() else None
        }
        
        # Create and start worker thread
        self.analysis_worker = AnalysisWorker(target_file, options)
        self.analysis_worker.progress_updated.connect(self.update_progress)
        self.analysis_worker.result_ready.connect(self.analysis_complete)
        self.analysis_worker.error_occurred.connect(self.analysis_error)
        
        # Update UI
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate progress
        
        # Clear previous results
        self.results_text.clear()
        self.files_tree.clear()
        self.memory_table.setRowCount(0)
        
        # Start analysis
        self.analysis_worker.start()
        
        self.log_message("🚀 Analysis started...")
        
    def stop_analysis(self):
        """Stop the analysis process."""
        if self.analysis_worker and self.analysis_worker.isRunning():
            self.analysis_worker.terminate()
            self.analysis_worker.wait()
            
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        self.log_message("⏹️ Analysis stopped.")
        
    def update_progress(self, message: str):
        """Update progress message."""
        self.status_bar.showMessage(message)
        self.log_message(message)
        
    def analysis_complete(self, results: Dict[str, Any]):
        """Handle analysis completion."""
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # Display results
        self.display_results(results)
        
        self.log_message("✅ Analysis completed successfully!")
        self.status_bar.showMessage("Analysis completed")
        
    def analysis_error(self, error: str):
        """Handle analysis error."""
        # Update UI
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.progress_bar.setVisible(False)
        
        # Show error
        QMessageBox.critical(self, "Analysis Error", f"Analysis failed: {error}")
        self.log_message(f"❌ Analysis failed: {error}")
        self.status_bar.showMessage("Analysis failed")
        
    def display_results(self, results: Dict[str, Any]):
        """Display analysis results."""
        # Update results text
        results_text = "=== ANALYSIS RESULTS ===\n\n"
        
        # Detection results
        if results.get('detection_result'):
            detection = results['detection_result']
            results_text += f"🔍 Packer Detected: {detection.get('packer', 'Unknown')}\n"
            results_text += f"📊 Confidence: {detection.get('confidence', 0)}%\n"
            results_text += f"🔧 Methods: {', '.join(detection.get('detection_methods', []))}\n\n"
            
        # Extraction results
        if results.get('extraction_result'):
            extraction = results['extraction_result']
            results_text += f"📦 Extraction: {'Success' if extraction.get('success') else 'Failed'}\n"
            if extraction.get('output_dir'):
                results_text += f"📁 Output Directory: {extraction['output_dir']}\n"
            if extraction.get('extracted_files'):
                results_text += f"📄 Files Extracted: {len(extraction['extracted_files'])}\n"
            if extraction.get('pyc_files'):
                results_text += f"🐍 Python Files: {len(extraction['pyc_files'])}\n"
            results_text += "\n"
            
        # Memory analysis results
        if results.get('memory_result'):
            memory = results['memory_result']
            results_text += f"🧠 Memory Analysis: {'Success' if memory.get('success') else 'Failed'}\n"
            if memory.get('dumps_created'):
                results_text += f"📊 Memory Dumps: {memory['dumps_created']}\n"
            results_text += "\n"
            
        # Deobfuscation results
        if results.get('deobfuscation_result'):
            deobfuscation = results['deobfuscation_result']
            results_text += f"🔓 Deobfuscation: {'Success' if deobfuscation.get('success') else 'Failed'}\n"
            if deobfuscation.get('decompiled_count'):
                results_text += f"📝 Decompiled Files: {deobfuscation['decompiled_count']}\n"
            results_text += "\n"
            
        self.results_text.setPlainText(results_text)
        
        # Update files tree
        self.update_files_tree(results)
        
        # Update memory table
        self.update_memory_table(results)
        
    def update_files_tree(self, results: Dict[str, Any]):
        """Update the files tree widget."""
        self.files_tree.clear()
        
        if results.get('extraction_result', {}).get('extracted_files'):
            root_item = QTreeWidgetItem(self.files_tree, ["Extracted Files"])
            root_item.setExpanded(True)
            
            for file_path in results['extraction_result']['extracted_files']:
                path = Path(file_path)
                item = QTreeWidgetItem(root_item, [
                    path.name,
                    path.suffix or "Unknown",
                    self.format_file_size(path.stat().st_size) if path.exists() else "Unknown"
                ])
                
    def update_memory_table(self, results: Dict[str, Any]):
        """Update the memory analysis table."""
        self.memory_table.setRowCount(0)
        
        if results.get('memory_result', {}).get('analysis_results', {}).get('memory_dumps'):
            for i, dump in enumerate(results['memory_result']['analysis_results']['memory_dumps']):
                self.memory_table.insertRow(i)
                self.memory_table.setItem(i, 0, QTableWidgetItem(dump.get('address', 'Unknown')))
                self.memory_table.setItem(i, 1, QTableWidgetItem(str(dump.get('size', 0))))
                self.memory_table.setItem(i, 2, QTableWidgetItem(dump.get('path', 'Unknown')))
                self.memory_table.setItem(i, 3, QTableWidgetItem("Dumped"))
                
    def format_file_size(self, size_bytes: int) -> str:
        """Format file size in human readable format."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/1024**2:.1f} MB"
        else:
            return f"{size_bytes/1024**3:.1f} GB"
            
    def log_message(self, message: str):
        """Add message to log."""
        timestamp = time.strftime("%H:%M:%S")
        self.log_text.append(f"[{timestamp}] {message}")
        
    def open_target_file(self):
        """Open target file action."""
        self.browse_target_file()
        
    def save_report(self):
        """Save analysis report."""
        if not hasattr(self, 'last_results'):
            QMessageBox.warning(self, "Warning", "No analysis results to save.")
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Analysis Report",
            "",
            "JSON Files (*.json);;Text Files (*.txt);;All Files (*.*)"
        )
        
        if file_path:
            try:
                if file_path.endswith('.json'):
                    with open(file_path, 'w') as f:
                        json.dump(self.last_results, f, indent=2)
                else:
                    with open(file_path, 'w') as f:
                        f.write(self.results_text.toPlainText())
                        
                QMessageBox.information(self, "Success", "Report saved successfully!")
                
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {e}")
                
    def show_settings(self):
        """Show settings dialog."""
        QMessageBox.information(self, "Settings", "Settings dialog not implemented yet.")
        
    def show_about(self):
        """Show about dialog."""
        about_text = """
        <h2>Unpacker Hydra</h2>
        <p><b>Advanced Python Executable Reverse Engineering Framework</b></p>
        <p>Version: 1.0.0</p>
        <p>A comprehensive tool for extracting and decompiling protected Python executables.</p>
        <p>Features:</p>
        <ul>
            <li>Packer Detection (PyInstaller, PyArmor, etc.)</li>
            <li>Memory Analysis and Dumping</li>
            <li>Bytecode Deobfuscation</li>
            <li>Advanced GUI Interface</li>
        </ul>
        <p>Built with PyQt6 and advanced reverse engineering libraries.</p>
        """
        
        QMessageBox.about(self, "About Unpacker Hydra", about_text)
        
    def run(self):
        """Run the GUI application."""
        self.show()
        return QApplication.instance().exec() 