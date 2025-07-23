#!/usr/bin/env python3

import os
import logging
import time
import shlex
from typing import Dict, Set, Optional, Any
from datetime import datetime, timezone
from scapy.all import rdpcap, IP, TCP, UDP, SCTP
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
import argparse
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from scapy.utils import wrpcap
from scapy.contrib.http2 import *
from scapy.config import conf
from h2_decoder import HTTP2Decoder

conf.use_pcap = True

# --- Configuration ---
IP_TO_ALIAS: Dict[str, str] = {
    "10.0.0.2": "amf",
    "10.0.0.3": "smf",
    "10.0.0.4": "upf",
    "10.0.0.5": "nrf",
    "10.0.0.6": "ausf",
    "10.0.0.7": "pcf",
    "10.0.0.8": "nssf",
    "10.0.0.9": "udm",
    "10.0.0.10": "udr",
    "10.0.0.12": "chf",
    "10.0.0.24": "nef",
    "10.0.1.0": "gnb",
}

IGNORE_IP_TO_ALIAS: Dict[str, str] = {
    "10.0.100.0": "db",
    "10.0.255.0": "webui",
    "10.0.255.1": "user-init",
}

# Processing configuration
PROCESSING_CONFIG = {
    # "output_dir": "/app/capture",
    "output_dir": "./capture",
    "file_prefix": "traffic",
    "processing_interval": 10,  # Process files every 3 seconds
    "file_stability_wait": 5,  # Wait 2 seconds to ensure file is stable
    "max_tracked_files": 100,  # Maximum files to track in processed_files set
    "merged_pcap": "./capture/merged.pcap",
}

# Global state
TARGET_IPS: Set[str] = set(IP_TO_ALIAS.keys())
processing_running = True
processed_files: Set[str] = set()
# Global variable to store the first capture start time
first_capture_start_time = None
# Global variable to store the total packet count
total_packets_count = 0
MONGO_URI = os.environ.get("MONGO_URI", "mongodb://localhost:27017/")

# --- Global storage for reconstructed payloads ---
# Each entry: {"to": dst_ip, "from": src_ip, "payload": ...}
reconstructed_payloads = []

# --- TCP stream reassembly buffers ---
# Key: (src_ip, src_port, dst_ip, dst_port), Value: bytearray
http2_stream_buffers = {}

# --- HTTP/1 outstanding requests for merging with responses ---
http1_outstanding_requests = {}

http2_decoder = None

# --- HTTP/1 methods ---
HTTP_METHODS = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "OPTIONS",
    "HEAD",
]

# MongoDB setup (singleton)
def init_mongo_collection():
    """
    Initializes the MongoDB collection for storing packet analysis results.
    
    Creates the "packet_analysis" collection in the "integration-tests" database if it does not already exist, and assigns it to the global variable for use in data insertion.
    """
    from pymongo import MongoClient
    from pymongo.errors import CollectionInvalid

    global mongo_collection
    mongo_client = MongoClient(MONGO_URI)
    mongo_db = mongo_client["integration-tests"]
    # Ensure collection exists
    try:
        mongo_db.create_collection("packet_analysis")
    except CollectionInvalid:
        pass  # Collection already exists
    mongo_collection = mongo_db["packet_analysis"]

def get_mongo_collection():
    """
    Retrieve the initialized MongoDB collection for packet analysis.
    
    Returns:
        The MongoDB collection instance if initialized; otherwise, None.
    """
    global mongo_collection
    if mongo_collection is None:
        logging.error("MongoDB collection is not initialized. Call init_mongo_collection() first.")
        return None
    return mongo_collection

def insert_packet_analysis(entry):
    """
    Insert a packet analysis document into the MongoDB collection if available.
    
    If the collection is unavailable or insertion fails, logs an error.
    """
    collection = get_mongo_collection()
    if collection is not None:
        try:
            collection.insert_one(entry)
        except Exception as e:
            logging.error(f"Failed to insert packet analysis into MongoDB: {e}")
    else:
        logging.error("Packet analysis entry not inserted: MongoDB collection unavailable.")

def parse_start_time_from_filename(filename):
    """
    Extracts a Unix timestamp from a pcap filename containing a 14-digit datetime string.
    
    Parameters:
    	filename (str): The pcap filename expected to end with a 14-digit timestamp (YYYYMMDDHHMMSS) followed by '.pcap'.
    
    Returns:
    	float: The extracted timestamp as seconds since the Unix epoch.
    
    Raises:
    	ValueError: If the filename does not contain a valid 14-digit timestamp before '.pcap'.
    """
    import re
    from datetime import datetime

    match = re.search(r"(\d{14})\.pcap$", filename)
    if not match:
        raise ValueError(f"Could not parse timestamp from {filename}")
    dt = datetime.strptime(match.group(1), "%Y%m%d%H%M%S")
    return dt.timestamp()


class ColoredFormatter(logging.Formatter):
    """Custom formatter for colored logging."""

    LIGHT_GREY = "\x1b[37;2m"
    GREEN = "\x1b[32;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    CYAN = "\x1b[36;20m"
    BLUE = "\x1b[34;20m"
    RESET = "\x1b[0m"

    def format(self, record):
        """
        Format a log record with color-coded level and timestamp for enhanced readability.
        
        Returns:
        	A formatted log message string with colored timestamp and log level based on message content and severity.
        """
        if "CAPTURED PAYLOAD" in record.msg:
            color = self.CYAN
        elif record.levelno >= logging.ERROR:
            color = self.RED
        elif record.levelno >= logging.WARNING:
            color = self.YELLOW
        else:
            color = self.GREEN

        timestamp = f"{self.LIGHT_GREY}{self.formatTime(record)}{self.RESET}"
        level = f"{color}{record.levelname}{self.RESET}"
        message = f"{record.getMessage()}"

        return f"{timestamp} - {level} - {message}"


def setup_logging(log_level=logging.INFO):
    """
    Configures the root logger with colored output and sets log levels for key modules.
    
    Sets up a stream handler with color formatting for log messages, applies the specified log level, and adjusts logging verbosity for scapy, watchdog, and h2_decoder modules.
    """
    handler = logging.StreamHandler()
    formatter = ColoredFormatter()
    handler.setFormatter(formatter)

    logger = logging.getLogger()
    logger.setLevel(log_level)
    logger.handlers.clear()
    logger.addHandler(handler)

    # Silence scapy warnings
    logging.getLogger("scapy").setLevel(logging.ERROR)
    logging.getLogger("watchdog").setLevel(logging.ERROR)
    logging.getLogger("h2_decoder").setLevel(log_level)
    logging.getLogger("h2_decoder").handlers.clear()
    logging.getLogger("h2_decoder").addHandler(handler)

def format_and_log_payload(
    proto: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, payload: bytes
) -> None:
    """
    Formats and logs detailed information about a captured network payload, including protocol, flow, timestamp, size, and a decoded or hexadecimal representation of the payload.
    """
    src = IP_TO_ALIAS.get(src_ip, src_ip)
    dst = IP_TO_ALIAS.get(dst_ip, dst_ip)

    log_lines = [
        "================ CAPTURED PAYLOAD ================",
        f"  Protocol: {proto}",
        f"  Flow:     {src}:{src_port} -> {dst}:{dst_port}",
        f"  Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}",
        f"  Size:     {len(payload)} bytes",
    ]

    # Try to decode payload
    try:
        if len(payload) > 0:
            decoded = payload.decode("utf-8", errors="replace")
            # Truncate very long payloads
            if len(decoded) > 1000:
                decoded = decoded[:1000] + "\n... (truncated)"
            log_lines.append(f"  Payload:\n{decoded}")
        else:
            log_lines.append("  Payload: (empty)")
    except Exception as e:
        log_lines.append(
            f"  Payload (hex): {payload.hex()[:200]}{'...' if len(payload) > 100 else ''}"
        )

    log_lines.append("=" * 50)
    logging.debug("\n".join(log_lines))


def analyze_sctp_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Analyzes an SCTP packet to identify the encapsulated protocol and extract relevant metadata.
    
    Returns:
        dict or None: A dictionary containing the detected protocol ("SCTP", "NGAP", or "S1AP"), source port, destination port, and payload bytes, or None if the packet does not contain an SCTP layer.
    """
    if not packet.haslayer(SCTP):
        return None

    sctp_layer = packet[SCTP]

    # Extract payload
    payload = b""
    if hasattr(sctp_layer, "payload") and sctp_layer.payload:
        payload = bytes(sctp_layer.payload)

    # Determine protocol based on payload protocol ID or port
    proto = "SCTP"
    if hasattr(sctp_layer, "payload_proto_id"):
        if sctp_layer.payload_proto_id == 60:
            proto = "NGAP"
        elif sctp_layer.payload_proto_id == 46:
            proto = "S1AP"

    return {
        "protocol": proto,
        "src_port": sctp_layer.sport,
        "dst_port": sctp_layer.dport,
        "payload": payload,
    }


def analyze_udp_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Analyzes a UDP packet to identify PFCP, GTP-U, or GTP-C protocols based on port numbers.
    
    Returns:
        dict or None: A dictionary containing the detected protocol name, source port, destination port, and payload bytes if the packet has a UDP layer; otherwise, None.
    """
    if not packet.haslayer(UDP):
        return None

    udp_layer = packet[UDP]

    # Extract payload
    payload = b""
    if hasattr(udp_layer, "payload") and udp_layer.payload:
        payload = bytes(udp_layer.payload)

    # Determine protocol based on port
    proto = "UDP"
    if udp_layer.sport == 8805 or udp_layer.dport == 8805:
        proto = "PFCP"
    elif udp_layer.sport == 2152 or udp_layer.dport == 2152:
        proto = "GTP-U"
    elif udp_layer.sport == 2123 or udp_layer.dport == 2123:
        proto = "GTP-C"

    return {
        "protocol": proto,
        "src_port": udp_layer.sport,
        "dst_port": udp_layer.dport,
        "payload": payload,
    }


def analyze_tcp_packet(packet) -> Optional[Dict[str, Any]]:
    """
    Analyzes a TCP packet to identify and extract HTTP request, HTTP response, or generic TCP payload information.
    
    Returns:
        dict or None: A dictionary containing the detected protocol type ("HTTP-REQ", "HTTP-RESP", or "TCP"), source port, destination port, and payload bytes. Returns None if the packet does not contain a TCP layer.
    """
    if not packet.haslayer(TCP):
        return None

    tcp_layer = packet[TCP]

    # Extract payload
    payload = b""
    proto = "TCP"

    # Check for HTTP
    if packet.haslayer(HTTPRequest):
        proto = "HTTP-REQ"
        payload = bytes(packet[HTTPRequest])
    elif packet.haslayer(HTTPResponse):
        proto = "HTTP-RESP"
        payload = bytes(packet[HTTPResponse])
    elif hasattr(tcp_layer, "payload") and tcp_layer.payload:
        payload = bytes(tcp_layer.payload)

        # Try to detect HTTP by looking at payload
        if (
            payload.startswith(b"GET ")
            or payload.startswith(b"POST ")
            or payload.startswith(b"PUT ")
        ):
            proto = "HTTP-REQ"
        elif payload.startswith(b"HTTP/"):
            proto = "HTTP-RESP"

    return {
        "protocol": proto,
        "src_port": tcp_layer.sport,
        "dst_port": tcp_layer.dport,
        "payload": payload,
    }


def format_payload_for_log(payload):
    """
    Format a payload string for logging, truncating it to 1000 characters if necessary.
    
    If the payload is a string shorter than 1000 characters, it is returned as-is. Otherwise, the payload is converted to a string and truncated to the first 1000 characters, followed by an ellipsis to indicate truncation.
    
    Returns:
        str: The formatted (possibly truncated) payload string.
    """
    if isinstance(payload, str) and len(payload) < 1000:
        return payload
    else:
        return str(payload)[:1000] + "... (truncated)"


def store_reconstructed_payload(
    protocol,
    src_ip,
    dst_ip,
    src_port,
    dst_port,
    req_headers=None,
    path=None,
    payload=None,
    request=None,
    response=None,
    resp_headers=None,
    resp_status=None,
    resp_reason=None,
    method=None,
    additional_data={},
):
    """
    Stores reconstructed protocol payload details, including metadata, headers, and bodies, in memory and MongoDB, and logs a formatted summary for analysis.
    
    Parameters:
        protocol (str): Protocol name (e.g., HTTP/1, HTTP/2, SCTP).
        src_ip (str): Source IP address.
        dst_ip (str): Destination IP address.
        src_port (int): Source port number.
        dst_port (int): Destination port number.
        req_headers (dict, optional): HTTP or protocol request headers.
        path (str, optional): Request path or resource identifier.
        payload (bytes or str, optional): Raw payload data.
        request (bytes or str, optional): Request body or content.
        response (bytes or str, optional): Response body or content.
        resp_headers (dict, optional): HTTP or protocol response headers.
        resp_status (int or str, optional): Response status code.
        resp_reason (str, optional): Response status reason phrase.
        method (str, optional): HTTP or protocol method.
        additional_data (dict, optional): Any extra parsed or protocol-specific data.
    
    The reconstructed payload is appended to a global list, inserted into the MongoDB collection, and a human-readable summary is logged.
    """
    src_ip_alias = IP_TO_ALIAS[src_ip]
    dst_ip_alias = IP_TO_ALIAS[dst_ip]
    entry = {
        "protocol": protocol,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "src_alias": src_ip_alias,
        "dst_alias": dst_ip_alias,
        "req_headers": req_headers,
        "resp_headers": resp_headers,
        "resp_status": resp_status,
        "resp_reason": resp_reason,
        "path": path,
        "payload": payload,
        "request": request,
        "response": response,
        "method": method,
        "additional_data": additional_data,
        "created_at": datetime.now(timezone.utc),
    }
    reconstructed_payloads.append(entry)
    # Store in MongoDB using helper
    insert_packet_analysis(entry)
    # Log the reconstructed payload in a readable format
    log_lines = [
        f"===== RECONSTRUCTED {protocol} PAYLOAD =====",
        f"  From: {src_ip}",
        f"  To:   {dst_ip}",
        f"  From Port: {src_port}",
        f"  To Port:   {dst_port}",
        f"  Src Alias: {src_ip_alias}",
        f"  Dst Alias: {dst_ip_alias}",
        f"  Method: {method}",
        f"  Path: {path}",
        f"  Req Headers: {req_headers}",
        f"  Resp Headers: {resp_headers}",
        f"  Resp Status: {resp_status}",
        f"  Resp Reason: {resp_reason}",
        f"  Request: {format_payload_for_log(request)}",
        f"  Response: {format_payload_for_log(response)}",
        f"  Payload: {format_payload_for_log(payload)}",
        f"  Additional Data: {format_payload_for_log(additional_data)}",
        "=" * 50,
    ]
    logging.info("\n".join(log_lines))


# --- HTTP/2 TCP stream reassembly and parsing ---
def process_tcp_packet_http2(packet, _src_ip, _dst_ip, _src_port, _dst_port, _payload):
    """
    Processes a TCP packet as HTTP/2, reconstructs streams, extracts headers and payloads, and stores the parsed data.
    
    For each HTTP/2 stream segment decoded from the packet, extracts method, path, status, headers, and payloads. Logs warnings for missing or unknown HTTP/2 fields. Stores the reconstructed HTTP/2 message in persistent storage.
    """
    global http2_decoder
    if http2_decoder is None:
        http2_decoder = HTTP2Decoder()
    results = http2_decoder.process_tcp_packet(packet)
    if results:
        for result in results:

            def find_in_pairs(pairs, key, default=None):
                """
                Return the value associated with a given key from a list of (key, value) pairs.
                
                Parameters:
                    pairs (list of tuple): List of (key, value) pairs to search.
                    key: The key to look for.
                    default: Value to return if the key is not found.
                
                Returns:
                    The value corresponding to the key if found; otherwise, the default value.
                """
                for k, v in pairs:
                    if k == key:
                        return v
                return default

            method = find_in_pairs(result.get("client_headers", []), ":method")
            path = find_in_pairs(result.get("client_headers", []), ":path")
            status = find_in_pairs(result.get("server_headers", []), ":status")
            if method and method not in HTTP_METHODS:
                logging.warning(
                    f"Unknown HTTP/2 method: {method} in packet {packet.summary()}"
                )
            if path is None:
                logging.warning(f"HTTP/2 packet missing path: {packet.summary()}")
            if status is None:
                logging.warning(f"HTTP/2 packet missing status: {packet.summary()}")

            payload = {
                "protocol": "HTTP/2",
                "src_ip": result["src_ip"],
                "dst_ip": result["dst_ip"],
                "src_port": result["src_port"],
                "dst_port": result["dst_port"],
                "req_headers": result.get("client_headers"),
                "resp_headers": result.get("server_headers"),
                "resp_status": result.get("resp_status"),
                "resp_reason": result.get("resp_reason"),
                "request": result.get("client_data"),
                "response": result.get("server_data"),
                "method": method,
                "path": path,
                "additional_data": {
                    "client_trailers": result.get("client_trailers"),
                    "server_trailers": result.get("server_trailers"),
                    "connection": result.get("connection", {}),
                },
            }
            store_reconstructed_payload(**payload)


# --- HTTP/1 parsing and merging ---
def process_tcp_packet_http1(packet, src_ip, dst_ip, src_port, dst_port, payload):
    # Note: No TCP reassembly is performed; each TCP packet is treated as a single HTTP message fragment.
    """
    Parses and processes a single HTTP/1.x message fragment from a TCP packet, reconstructing and storing HTTP requests or responses.
    
    Attempts to distinguish between HTTP requests and responses based on the payload, extracting headers, method, path, status, and body. Requests are stored for later matching with responses. When a response is detected, it is merged with the corresponding stored request if available; otherwise, the response is stored standalone. Unclassified fragments are stored as-is. All reconstructed data is passed to the payload storage function for logging and persistence.
    """
    try:
        payload_str = payload.decode("utf-8", errors="replace")
        # Split headers and body
        if "\r\n\r\n" in payload_str:
            header_part, body = payload_str.split("\r\n\r\n", 1)
        else:
            header_part, body = payload_str, ""
        headers = {}
        path = ""
        resp_status = None
        resp_reason = None
        lines = header_part.split("\r\n")
        is_request = False
        is_response = False
        method = None
        if lines:
            first = lines[0].split()
            # Heuristic: request line starts with method, response with HTTP/
            if len(first) >= 2 and first[0] in HTTP_METHODS:
                is_request = True
                method = first[0]
                path = first[1]
            elif len(first) >= 2 and first[0].startswith("HTTP/"):
                is_response = True
                resp_status = first[1]
                resp_reason = " ".join(first[2:]) if len(first) > 2 else None
            for line in lines[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip()] = v.strip()
        # Only store one of request or response per packet
        payload_dict = {
            "headers": headers,
            "path": path,
        }
        if is_request:
            payload_dict["request"] = body
            # Store request for this connection
            key = (src_ip, src_port, dst_ip, dst_port)
            http1_outstanding_requests[key] = {
                "protocol": "HTTP/1",
                "from": src_ip,
                "to": dst_ip,
                "headers": headers,
                "path": path,
                "request": body,
                "method": method,
            }
            logging.debug(f"[HTTP/1] Stored request for {key}")
        elif is_response:
            # Try to find matching request
            key = (dst_ip, dst_port, src_ip, src_port)
            merged = None
            if key in http1_outstanding_requests:
                req = http1_outstanding_requests.pop(key)
                # For HTTP/1 responses, the source and destination sockets are reversed to match the original request direction
                merged = {
                    "protocol": "HTTP/1",
                    "src_ip": dst_ip,
                    "dst_ip": src_ip,
                    "src_port": dst_port,
                    "dst_port": src_port,
                    "method": req["method"],
                    "req_headers": req["headers"],
                    "path": req["path"],
                    "request": req["request"],
                    "resp_headers": headers,
                    "resp_status": resp_status,
                    "resp_reason": resp_reason,
                    "response": body,
                    "payload": None,
                }
                store_reconstructed_payload(**merged)
                logging.debug(
                    f"[HTTP/1] Merged request/response for {key} status={resp_status} reason={resp_reason}"
                )
            else:
                # No matching request, store response standalone
                store_reconstructed_payload(
                    "HTTP/1",
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    resp_headers=headers,
                    path=path,
                    response=body,
                    resp_status=resp_status,
                    resp_reason=resp_reason,
                )
                logging.debug(
                    f"[HTTP/1] Standalone response for {key} status={resp_status} reason={resp_reason}"
                )
        else:
            # Unknown/fragment, just store as-is
            logging.error(
                f"[HTTP/1] Unclassified fragment for {src_ip}:{src_port}->{dst_ip}:{dst_port} {payload}"
            )
            store_reconstructed_payload(
                "HTTP/1", src_ip, dst_ip, src_port, dst_port, payload=payload
            )

    except Exception as e:
        logging.debug(f"HTTP/1 parsing error: {e}")


# --- SCTP storage ---
def process_sctp_packet_store(packet, src_ip, dst_ip, src_port, dst_port, payload):
    """
    Stores the payload of an SCTP packet for analysis and logging.
    
    This function records the SCTP packet's payload along with its source and destination information by delegating to the payload storage mechanism.
    """
    store_reconstructed_payload(
        "SCTP", src_ip, dst_ip, src_port, dst_port, None, None, payload
    )


def log_l4_packet(proto, src_ip, dst_ip, src_port, dst_port, payload):
    """
    Log a summary of a Layer 4 or higher network packet, including protocol, endpoints, and a truncated payload.
    
    The payload is displayed as a hexadecimal string if it is bytes, or as a string otherwise, truncated to 200 characters.
    """
    log_lines = [
        f"----- L4+ PACKET -----",
        f"  Protocol: {proto}",
        f"  From: {src_ip}:{src_port}",
        f"  To:   {dst_ip}:{dst_port}",
        f"  Payload: {payload[:200].hex() if isinstance(payload, bytes) else str(payload)[:200]}{'... (truncated)' if len(payload) > 200 else ''}",
        "-" * 40,
    ]
    logging.debug("\n".join(log_lines))


# --- Unified process_packet ---
def process_packet(packet) -> None:
    """
    Processes a single network packet, filtering by target and ignored IPs, and dispatches protocol-specific analysis and logging.
    
    The function checks if the packet involves monitored IP addresses and is not from ignored IPs. It then determines the protocol (SCTP, TCP, or UDP), logs relevant payload information, and invokes the appropriate handler for further analysis and storage. For TCP packets, it heuristically distinguishes between HTTP/2 and HTTP/1 traffic and processes accordingly, with fallback handling for ambiguous cases.
    """
    if not packet.haslayer(IP):
        return
    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    # Check if packet involves target IPs
    if src_ip not in TARGET_IPS and dst_ip not in TARGET_IPS:
        return
    # Check if packet involves ignored IPs
    if src_ip in IGNORE_IP_TO_ALIAS or dst_ip in IGNORE_IP_TO_ALIAS:
        return
    # Analyze packet based on protocol
    if packet.haslayer(SCTP):
        sctp_layer = packet[SCTP]
        payload = (
            bytes(sctp_layer.payload)
            if hasattr(sctp_layer, "payload") and sctp_layer.payload
            else b""
        )
        format_and_log_payload(
            "SCTP", src_ip, dst_ip, sctp_layer.sport, sctp_layer.dport, payload
        )
        process_sctp_packet_store(
            packet, src_ip, dst_ip, sctp_layer.sport, sctp_layer.dport, payload
        )
    elif packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        payload = (
            bytes(tcp_layer.payload)
            if hasattr(tcp_layer, "payload") and tcp_layer.payload
            else b""
        )
        format_and_log_payload(
            "TCP", src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, payload
        )
        # Heuristic: HTTP/2 uses magic preface or :method header, HTTP/1 uses GET/POST/PUT/HTTP/
        if payload.startswith(b"PRI * HTTP/2.0") or b":method" in payload:
            process_tcp_packet_http2(
                packet, src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, payload
            )
        elif any(
            payload.startswith(method.encode() + b" ") for method in HTTP_METHODS
        ) or payload.startswith(b"HTTP/"):
            process_tcp_packet_http1(
                packet, src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, payload
            )
        else:
            # Try both, fallback to HTTP/1
            try:
                process_tcp_packet_http2(
                    packet, src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, payload
                )
            except Exception as e:
                logging.exception(f"Error processing packet as HTTP/2: {e}")
                import traceback

                logging.error(f"Exception traceback:\n{traceback.format_exc()}")
                process_tcp_packet_http1(
                    packet, src_ip, dst_ip, tcp_layer.sport, tcp_layer.dport, payload
                )
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        payload = (
            bytes(udp_layer.payload)
            if hasattr(udp_layer, "payload") and udp_layer.payload
            else b""
        )
        format_and_log_payload(
            "UDP", src_ip, dst_ip, udp_layer.sport, udp_layer.dport, payload
        )
        result = analyze_udp_packet(packet)
    elif packet.haslayer(TCP):
        result = analyze_tcp_packet(packet)


def process_pcap_file(pcap_file: str) -> None:
    """
    Processes all packets in a given pcap file, analyzing each packet and updating the total processed packet count.
    
    Parameters:
        pcap_file (str): Path to the pcap file to be processed.
    """
    global total_packets_count
    try:
        logging.info(f"Processing: {os.path.basename(pcap_file)}")
        # Read and adjust packets (function manages global start time)
        packets = rdpcap(pcap_file)
        processed_count = 0
        for packet in packets:
            process_packet(packet)
            processed_count += 1
            total_packets_count += 1

        logging.info(
            f"Processed {processed_count} packets from {os.path.basename(pcap_file)}, total packets processed: {total_packets_count}"
        )
    except Exception as e:
        logging.error(f"Error processing {pcap_file}: {e}")


def is_file_stable(file_path: str) -> bool:
    """
    Determine whether a file's size remains unchanged over a configured interval, indicating it is no longer being written to.
    
    Parameters:
        file_path (str): Path to the file to check.
    
    Returns:
        bool: True if the file size is stable, False if it changes or the file is inaccessible.
    """
    try:
        initial_size = os.path.getsize(file_path)
        time.sleep(PROCESSING_CONFIG["file_stability_wait"])

        if not os.path.exists(file_path):
            return False

        current_size = os.path.getsize(file_path)
        return initial_size == current_size
    except OSError:
        return False


def cleanup_processed_files():
    """
    Removes older entries from the processed_files set to limit its size.
    
    Retains only the most recently created files, ensuring the set does not exceed half of the configured maximum tracked files.
    """
    global processed_files
    if len(processed_files) > PROCESSING_CONFIG["max_tracked_files"]:
        # Keep only the most recent files
        file_list = list(processed_files)
        file_list.sort(key=lambda x: os.path.getctime(x) if os.path.exists(x) else 0)
        processed_files = set(file_list[-PROCESSING_CONFIG["max_tracked_files"] // 2 :])


def main_processing_loop_tshark_out(tshark_out_path: str):
    """
    Continuously monitors a tshark output file for new pcap file entries, processes each new file when stable, and manages processed file tracking.
    
    Watches the specified tshark output file for modifications using watchdog. When new pcap file paths are detected, ensures each file is stable before processing its packets. Tracks processed files to avoid duplicates and periodically cleans up the tracking set. Runs until interrupted or signaled to stop.
    """
    global processed_files
    last_offset = 0

    def process_file_lines(lines):
        """
        Processes a list of file paths by checking their stability and processing new pcap files.
        
        Each file is processed only if it has not been handled before and is determined to be stable. After processing, the file is marked as processed and the set of tracked files is cleaned up to manage memory usage.
        
        Parameters:
            lines (list of str): List of file paths to process.
        """
        for fname in lines:
            fname = fname.strip()
            if fname and fname not in processed_files:
                logging.info(f"Processing file: {fname}")
                if is_file_stable(fname):
                    process_pcap_file(fname)
                    processed_files.add(fname)
                    cleanup_processed_files()

    logging.info("=== Python Packet Processor Started ===")
    logging.info(f"Watching tshark output: {tshark_out_path} (using watchdog)")
    logging.info("-" * 50)

    # First, process any existing lines in the file
    if os.path.exists(tshark_out_path):
        with open(tshark_out_path, "r") as f:
            f.seek(0)
            lines = f.readlines()
            last_offset = f.tell()
        process_file_lines(lines)

    class TsharkOutHandler(FileSystemEventHandler):
        def on_modified(self, event):
            """
            Handles file modification events for the tshark output file, reads new lines since the last offset, and processes them.
            
            Parameters:
            	event: The file system event indicating a modification.
            """
            nonlocal last_offset
            if event.src_path != os.path.abspath(tshark_out_path):
                return
            try:
                with open(tshark_out_path, "r") as f:
                    f.seek(last_offset)
                    new_lines = f.readlines()
                    last_offset = f.tell()
                process_file_lines(new_lines)
            except Exception as e:
                logging.error(f"Error reading tshark output: {e}")

    event_handler = TsharkOutHandler()
    observer = Observer()
    observer.schedule(
        event_handler,
        path=os.path.dirname(os.path.abspath(tshark_out_path)) or ".",
        recursive=False,
    )
    observer.start()
    try:
        while processing_running:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("Received interrupt signal")
    finally:
        observer.stop()
        observer.join()


def signal_handler(signum, frame):
    """
    Handles process termination signals by logging the event and setting the processing flag to stop the main loop.
    """
    global processing_running
    logging.info(f"Received signal {signum}, shutting down...")
    processing_running = False


def build_tshark_command():
    """
    Construct and return a tshark command configured to capture relevant network traffic.
    
    The command captures TCP packets with the PSH flag set, all UDP packets, and SCTP packets with chunk type 0 (DATA), filtering for specified target IPs and excluding ignored IPs. The resulting command includes options for interface selection, capture filters, output file, and file rotation.
     
    Returns:
        list: The tshark command as a list of arguments suitable for subprocess execution.
    """
    # TCP: PSH flag set (data transfer)
    tcp_psh_condition = "tcp and tcp[13] & 8 != 0"  # PSH flag
    # UDP: All UDP packets
    udp_condition = "udp"
    # SCTP: First chunk type == 0 (DATA chunk)
    sctp_init_condition = "sctp and sctp[12] == 0"  # DATA  chunk

    # Build host filter from IP_TO_ALIAS
    host_ips = list(IP_TO_ALIAS.keys())
    host_filter = " or ".join(f"host {ip}" for ip in host_ips)

    # Build ignore filter from IGNORE_IP_TO_ALIAS
    ignore_ips = list(IGNORE_IP_TO_ALIAS.keys())
    ignore_filter = " and ".join(f"not host {ip}" for ip in ignore_ips)

    # Capture only payload-carrying chunks: TCP packets with PSH flag (likely carrying data), all UDP packets, and SCTP packets with chunk type 0 (typically DATA or INIT).
    # Only packets where at least one endpoint (source or destination IP) matches the host filter are included.
    # Any packet where either endpoint matches the ignore list is excluded, even if the other endpoint is in the host list.
    capture_filter = (
        f"(({tcp_psh_condition}) or ({udp_condition}) or ({sctp_init_condition})) "
        f"and ({host_filter}) "
        f"and ({ignore_filter})"
    )

    # Log all filters
    logging.info(f"TCP PSH filter: {tcp_psh_condition}")
    logging.info(f"UDP filter: {udp_condition}")
    logging.info(f"SCTP INIT filter: {sctp_init_condition}")
    logging.info(f"Host filter: {host_filter}")
    logging.info(f"Ignore filter: {ignore_filter}")
    logging.info(f"Final capture filter: {capture_filter}")

    # Compose the tshark command
    return [
        "tshark",
        "-i",
        "br-unifyair",
        "-f",
        capture_filter,
        "-w",
        "/app/capture/traffic.pcap",
        "-l",
        "-b",
        "duration:30",
        "-b",
        "packets:10",
        "-q",
        "-b",
        "printname:stdout",
    ]


def main():
    """
    Entry point for the packet processor CLI, handling argument parsing, logging setup, and execution mode selection.
    
    Depending on the selected mode, either prints the tshark capture command or processes pcap files listed in the specified tshark output file. Initializes MongoDB integration and manages the main processing loop for packet analysis.
    """
    parser = argparse.ArgumentParser(
        description="Packet processor for tshark pcap output."
    )
    parser.add_argument(
        "--tshark-out",
        type=str,
        help="Path to tshark's stdout file (required if --mode process)",
    )
    parser.add_argument(
        "--mode",
        type=str,
        required=True,
        choices=["process", "build-tshark-cmd"],
        help="Mode: 'process' to process pcap files, 'build-tshark-cmd' to print the tshark command and exit.",
    )
    parser.add_argument(
        "--log-level",
        type=str,
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level: DEBUG, INFO, WARNING, ERROR, CRITICAL (default: INFO)",
    )
    args = parser.parse_args()

    # Convert log level string to logging constant
    log_level = getattr(logging, args.log_level.upper(), logging.INFO)
    setup_logging(log_level)

    if args.mode == "build-tshark-cmd":
        cmd = build_tshark_command()
        logging.info("Tshark command:")
        logging.info(" ".join(shlex.quote(str(x)) for x in cmd))
        return

    if args.mode == "process" and not args.tshark_out:
        parser.error("--tshark-out is required when --mode is 'process'")
    tshark_out_path = args.tshark_out
    if not os.path.exists(tshark_out_path):
        parser.error(f"Tshark output file does not exist: {tshark_out_path}")
    init_mongo_collection()
    main_processing_loop_tshark_out(tshark_out_path)
    logging.info(f"Total packets processed: {total_packets_count}")
    logging.info("Exited")


if __name__ == "__main__":
    main()
