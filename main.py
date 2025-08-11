#!/usr/bin/env python3
"""
Unpacker Hydra - Advanced Python Executable Reverse Engineering Framework
A comprehensive tool for extracting and decompiling protected Python executables.
"""

import argparse
import sys
import os
from pathlib import Path
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt
import colorama

from core.detector import PackerDetector
from core.extractor import Extractor
from core.memory_dumper import MemoryDumper
from core.bytecode_deobfuscator import BytecodeDeobfuscator
from utils.logger import Logger
from gui.main_window import UnpackerHydraGUI

# Initialize colorama for Windows
colorama.init()

class UnpackerHydra:
    def __init__(self):
        self.console = Console()
        self.logger = Logger()
        self.detector = PackerDetector()
        self.extractor = Extractor()
        self.memory_dumper = MemoryDumper()
        self.deobfuscator = BytecodeDeobfuscator()
        
    def print_banner(self):
        """Display the cyberpunk-inspired banner."""
        banner = """
[bold cyan]╔══════════════════════════════════════════════════════════════════════════════╗[/bold cyan]
[bold cyan]║[/bold cyan]  [bold magenta]██╗   ██╗███╗   ██╗██████╗  █████╗  ██████╗██╗  ██╗███████╗██████╗[/bold magenta]  [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold magenta]██║   ██║████╗  ██║██╔══██╗██╔══██╗██╔════╝██║ ██╔╝██╔════╝██╔══██╗[/bold magenta] [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold magenta]██║   ██║██╔██╗ ██║██████╔╝███████║██║     █████╔╝ █████╗  ██████╔╝[/bold magenta] [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold magenta]██║   ██║██║╚██╗██║██╔═══╝ ██╔══██║██║     ██╔═██╗ ██╔══╝  ██╔══██╗[/bold magenta] [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold magenta]╚██████╔╝██║ ╚████║██║     ██║  ██║╚██████╗██║  ██╗███████╗██║  ██║[/bold magenta] [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]   [bold magenta]╚═════╝ ╚═╝  ╚═══╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝[/bold magenta]   [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]                                                                              [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [bold green]H Y D R A[/bold green] - [bold yellow]Advanced Python Executable Reverse Engineering[/bold yellow]  [bold cyan]║[/bold cyan]
[bold cyan]║[/bold cyan]  [dim]Extract • Decompile • Analyze • Bypass[/dim]                              [bold cyan]║[/bold cyan]
[bold cyan]╚══════════════════════════════════════════════════════════════════════════════╝[/bold cyan]
        """
        self.console.print(banner)
        
    def analyze_target(self, target_path, options):
        """Main analysis pipeline."""
        target_path = Path(target_path)
        
        if not target_path.exists():
            self.console.print(f"[red]Error: Target file '{target_path}' not found![/red]")
            return False
            
        self.console.print(f"\n[bold cyan]🎯 Target:[/bold cyan] {target_path}")
        self.console.print(f"[bold cyan]📊 Size:[/bold cyan] {target_path.stat().st_size:,} bytes")
        
        # Phase 1: Packer Detection
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Detecting packer/protection...", total=None)
            
            detection_result = self.detector.detect_packer(target_path)
            progress.update(task, completed=True)
            
        if detection_result:
            self.console.print(f"[green]✅ Detected:[/green] {detection_result['packer']} (Confidence: {detection_result['confidence']}%)")
        else:
            self.console.print("[yellow]⚠️  No known packer detected - attempting generic analysis[/yellow]")
            
        # Phase 2: Extraction
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console
        ) as progress:
            task = progress.add_task("Extracting files...", total=None)
            
            extraction_result = self.extractor.extract(target_path, detection_result, options)
            progress.update(task, completed=True)
            
        if extraction_result['success']:
            self.console.print(f"[green]✅ Extraction successful![/green] Files saved to: {extraction_result['output_dir']}")
            
            # Phase 3: Memory Analysis (if enabled)
            if options.get('memory_analysis', False):
                self.console.print("\n[bold cyan]🧠 Starting memory analysis...[/bold cyan]")
                memory_result = self.memory_dumper.analyze_memory(target_path, extraction_result)
                
            # Phase 4: Deobfuscation
            if extraction_result.get('pyc_files'):
                self.console.print("\n[bold cyan]🔓 Deobfuscating bytecode...[/bold cyan]")
                deobfuscation_result = self.deobfuscator.deobfuscate_all(
                    extraction_result['pyc_files'], 
                    extraction_result['output_dir']
                )
                
                if deobfuscation_result['success']:
                    self.console.print(f"[green]✅ Deobfuscation complete![/green] {deobfuscation_result['decompiled_count']} files processed")
                    
        else:
            self.console.print(f"[red]❌ Extraction failed: {extraction_result['error']}[/red]")
            return False
            
        return True
        
    def run_cli(self, args):
        """Run the CLI interface."""
        self.print_banner()
        
        options = {
            'dry_run': args.dry_run,
            'memory_analysis': args.memory,
            'stealth_mode': args.stealth,
            'verbose': args.verbose,
            'output_dir': args.output,
            'plugin_path': args.plugin
        }
        
        if args.gui:
            self.run_gui()
        else:
            if not args.target:
                self.console.print("[red]Error: Target file is required![/red]")
                self.console.print("Use --help for usage information.")
                return
                
            success = self.analyze_target(args.target, options)
            
            if success:
                self.console.print("\n[bold green]🎉 Analysis complete![/bold green]")
            else:
                self.console.print("\n[bold red]💥 Analysis failed![/bold red]")
                
    def run_gui(self):
        """Launch the GUI interface."""
        self.console.print("[cyan]Launching GUI interface...[/cyan]")
        app = UnpackerHydraGUI()
        app.run()

def main():
    parser = argparse.ArgumentParser(
        description="Unpacker Hydra - Advanced Python Executable Reverse Engineering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py target.exe                    # Basic analysis
  python main.py target.exe --memory          # With memory analysis
  python main.py target.exe --stealth         # Stealth mode
  python main.py --gui                        # Launch GUI
  python main.py target.exe --dry-run         # Preview only
        """
    )
    
    parser.add_argument('target', nargs='?', help='Target executable file to analyze')
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    parser.add_argument('--memory', action='store_true', help='Enable memory analysis mode')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (anti-detection)')
    parser.add_argument('--dry-run', action='store_true', help='Preview analysis without extraction')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    parser.add_argument('--output', '-o', help='Output directory for extracted files')
    parser.add_argument('--plugin', '-p', help='Custom plugin directory')
    
    args = parser.parse_args()
    
    try:
        hydra = UnpackerHydra()
        hydra.run_cli(args)
    except KeyboardInterrupt:
        print("\n[red]Operation cancelled by user[/red]")
    except Exception as e:
        print(f"\n[red]Fatal error: {e}[/red]")
        if args.verbose:
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main() 