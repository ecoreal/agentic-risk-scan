"""Static security scanner for AI agent workflows and MCP configs."""

from .models import Finding, Location, ScanConfig, ScanResult
from .scanner import scan_path

__all__ = ["Finding", "Location", "ScanConfig", "ScanResult", "scan_path"]

__version__ = "0.5.0"
