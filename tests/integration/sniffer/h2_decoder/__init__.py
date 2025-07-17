"""
HTTP/2 PCAP Decoder Package

A comprehensive package for decoding HTTP/2 traffic from PCAP files.
Handles HTTP/2 frames, HPACK compression, and connection state management.

Classes:
    HTTP2Decoder: Main decoder class for HTTP/2 PCAP analysis
    HTTP2Connection: Manages HTTP/2 connection state and HPACK context
    HTTP2Stream: Represents an HTTP/2 stream with headers and data

Functions:
    debug_frame_parsing: Debug function to examine raw HTTP/2 frame structure
"""

from .decoder import HTTP2Decoder
from .connection import HTTP2Connection
from .stream import HTTP2Stream

__version__ = "1.0.0"
__author__ = "HTTP/2 PCAP Decoder"

__all__ = [
    'HTTP2Decoder',
    'HTTP2Connection', 
    'HTTP2Stream',
] 