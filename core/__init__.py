"""
Core Module for Unpacker Hydra
Advanced Python executable reverse engineering framework.
"""

from .detector import PackerDetector
from .extractor import Extractor
from .memory_dumper import MemoryDumper
from .bytecode_deobfuscator import BytecodeDeobfuscator

__version__ = "1.0.0"
__author__ = "Unpacker Hydra Team"

__all__ = [
    'PackerDetector',
    'Extractor', 
    'MemoryDumper',
    'BytecodeDeobfuscator'
] 