"""
Plugins Module for Unpacker Hydra
Extensible plugin system for different packer types.
"""

from .pyinstaller import PyInstallerPlugin
from .pyarmor import PyArmorPlugin

__version__ = "1.0.0"
__author__ = "Unpacker Hydra Team"

__all__ = [
    'PyInstallerPlugin',
    'PyArmorPlugin'
] 