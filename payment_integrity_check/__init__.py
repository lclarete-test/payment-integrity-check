"""Local static checks for payment data integrity."""

from .analyzer import Finding, scan

__all__ = ["Finding", "scan"]
__version__ = "0.1.0"
