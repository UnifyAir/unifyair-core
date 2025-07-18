import struct
from collections import defaultdict, OrderedDict
from scapy.all import rdpcap, TCP, IP
from .connection import HTTP2Connection
from .stream import HTTP2Stream

from hyperframe.frame import (
    DataFrame, HeadersFrame, SettingsFrame, WindowUpdateFrame,
    PushPromiseFrame, GoAwayFrame, PingFrame, RstStreamFrame, PriorityFrame
)
from .utils import logger

class HTTP2Decoder:
    """
    Main decoder class for HTTP/2 PCAP analysis.
    Manages TCP stream aggregation and HTTP/2 parsing incrementally.
    """
    def __init__(self):
        # Key: (canonical_src_ip, canonical_dst_ip, canonical_src_port, canonical_dst_port)
        # Value: HTTP2Connection object
        self.connections = {}
        self.http2_preface = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
        self.total_packets_processed = 0 # Counter for logging/debugging

    def process_pcap(self, pcap_file):
        """
        Processes a PCAP file packet by packet, extracts TCP packets with PSH flag,
        and attempts to reconstruct HTTP/2 sessions incrementally.
        """
        logger.info(f"Loading and processing packets from {pcap_file}...")
        packets = rdpcap(pcap_file)
        logger.info(f"Loaded {len(packets)} packets.")
        
        for packet in packets:
            if TCP in packet and packet[TCP].flags.P:  # Check for PSH flag (Push data)
                results = self.process_tcp_packet(packet)
                if results:
                    for result in results:
                        logger.info("--- Stream Completed ---")
                        logger.info(f"Stream ID: {result['stream_id']}")
                        logger.info(f"Connection: {result['connection']['client_addr'][0]}:{result['connection']['client_addr'][1]} <-> {result['connection']['server_addr'][0]}:{result['connection']['server_addr'][1]}")
                        logger.info(f"Connection Settings: {result['connection']['settings']}")
                        logger.info(f"  Client IP: {result['src_ip']}:{result['src_port']}")
                        logger.info(f"  Server IP: {result['dst_ip']}:{result['dst_port']}")
                        logger.info(f"  Client Complete: {result['client_complete']}")
                        logger.info(f"  Server Complete: {result['server_complete']}")
                        if result['client_trailers']:
                            logger.info(f"  Client Trailers: {result['client_trailers']}")
                        if result['server_trailers']:
                            logger.info(f"  Server Trailers: {result['server_trailers']}")  
                        logger.info("  --- Client Request Headers ---")
                        for name, value in result['client_headers']:
                            logger.info(f"    {name}: {value}")
                        logger.info("  --- Server Response Headers ---")
                        for name, value in result['server_headers']:
                            logger.info(f"    {name}: {value}")
                        if result['client_data']:
                            logger.debug(f"  --- Client Data ({len(result['client_data'])} bytes) ---")
                            logger.debug(result['client_data'][:500])  # Truncate if needed
                        if result['server_data']:
                            logger.debug(f"  --- Server Data ({len(result['server_data'])} bytes) ---")
                            logger.debug(result['server_data'][:500])  # Truncate if needed
                        logger.info("-"*50)

        logger.info("Finished processing all packets.")
        logger.info("\n--- Summary of HTTP/2 Connections ---")
       

    def process_tcp_packet(self, packet):
        """
        Processes a single TCP packet, identifies its direction within an HTTP/2 connection,
        adds its payload to the appropriate buffer, and attempts to parse HTTP/2 frames.
        Returns a list of dicts with request/response data for all streams that ended due to this packet.
        """
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]
        packet_src_addr = (ip_layer.src, tcp_layer.sport)
        packet_dst_addr = (ip_layer.dst, tcp_layer.dport)
        self.total_packets_processed += 1 
        payload = bytes(tcp_layer.payload)
        if not payload:
            return []

        # Create a canonical tuple for consistent connection identification (e.g., always lower IP first)
        if packet_src_addr < packet_dst_addr:
            canonical_conn_tuple = (packet_src_addr[0], packet_dst_addr[0], packet_src_addr[1], packet_dst_addr[1])
        else:
            canonical_conn_tuple = (packet_dst_addr[0], packet_src_addr[0], packet_dst_addr[1], packet_src_addr[1])
            
        connection = self.connections.get(canonical_conn_tuple)

        # Handle new connections or connections where preface hasn't been seen yet
        if connection is None:
            preface_offset = payload.find(self.http2_preface)
            if preface_offset != -1:
                logger.info(f"Detected HTTP/2 preface from client {packet_src_addr[0]}:{packet_src_addr[1]} to server {packet_dst_addr[0]}:{packet_dst_addr[1]} (Packet #{self.total_packets_processed})")
                connection = HTTP2Connection(packet_src_addr, packet_dst_addr)
                connection.preface_seen = True
                self.connections[canonical_conn_tuple] = connection
                connection.ended_stream_ids = set()  # Track ended streams
                connection.client_buffer += payload[preface_offset + len(self.http2_preface):]
                self.parse_http2_frames_from_buffer(connection, from_client=True)
                # Check for completed streams
                completed = self._collect_and_remove_completed_streams(connection)
                return completed
            else:
                return []
        
        if not hasattr(connection, 'ended_stream_ids'):
            connection.ended_stream_ids = set()
        is_packet_from_connection_client = (packet_src_addr == connection.client_addr)

        if is_packet_from_connection_client:
            connection.client_buffer += payload
            self.parse_http2_frames_from_buffer(connection, from_client=True)
        else:
            connection.server_buffer += payload
            self.parse_http2_frames_from_buffer(connection, from_client=False)

        completed = self._collect_and_remove_completed_streams(connection)
        return completed

    def _collect_and_remove_completed_streams(self, connection):
        """
        Helper to collect all completed streams, remove them from the connection,
        and return their data as a list of dicts. Keeps track of ended stream IDs.
        """
        completed = []
        to_remove = []
        for stream_id, stream in connection.streams.items():
            if stream.server_complete and stream.client_complete and stream_id not in connection.ended_stream_ids:
                completed.append(self._stream_to_dict(connection, stream))
                to_remove.append(stream_id)
        for stream_id in to_remove:
            connection.ended_stream_ids.add(stream_id)
            del connection.streams[stream_id]
        return completed

    def _stream_to_dict(self, connection, stream):
        """
        Helper to convert a completed stream to a dict with request and response data.
        """
        src_ip, src_port = connection.client_addr
        dst_ip, dst_port = connection.server_addr
        
        # Convert headers and data to lists of tuples for easier JSON serialization
        return {
            'src_ip': src_ip,
            'src_port': src_port,
            'dst_ip': dst_ip,
            'dst_port': dst_port,
            'stream_id': stream.stream_id,
            'client_headers': stream.client_headers,
            'client_data': stream.client_data,
            'server_headers': stream.server_headers,
            'server_data': stream.server_data,
            'client_trailers': stream.client_trailers,
            'server_trailers': stream.server_trailers,
            'client_complete': stream.client_complete,
            'server_complete': stream.server_complete,
            'connection': {
                'client_addr': connection.client_addr,
                'server_addr': connection.server_addr,
                'settings': connection.settings.copy(),
            }
        }

    def parse_http2_frames_from_buffer(self, connection, from_client):
        """
        Attempts to parse HTTP/2 frames from a connection's buffer (client_buffer or server_buffer).
        Consumes successfully parsed data from the buffer.
        """
        current_buffer = connection.client_buffer if from_client else connection.server_buffer
        
        offset = 0

        while offset <= len(current_buffer) - 9: # Need at least 9 bytes for frame header
            try:
                frame_header = current_buffer[offset:offset + 9]
                length = struct.unpack('>I', b'\x00' + frame_header[:3])[0] # Length is 24-bit
                frame_type = frame_header[3]
                flags = frame_header[4]
                stream_id = struct.unpack('>I', frame_header[5:9])[0] & 0x7FFFFFFF # Stream ID is 31-bit

                # Check if the full frame (header + body) is available in the buffer
                if offset + 9 + length > len(current_buffer):
                    # Not enough data for the full frame, break the loop and wait for more data
                    break

                frame_body = current_buffer[offset + 9:offset + 9 + length]

                frame = self._create_hyperframe_object(frame_type, flags, stream_id, frame_body)

                if frame:
                    if stream_id > 0: # Stream-specific frame
                        if stream_id not in connection.streams:
                            connection.streams[stream_id] = HTTP2Stream(stream_id)
                        self.handle_frame(frame, connection.streams[stream_id], connection, from_client)
                    else: # Connection-level frame (Stream ID 0)
                        self._handle_connection_frame(frame, connection, from_client)
                
                offset += 9 + length # Move offset past the current frame
            except Exception as e:
                logger.error(f"Error parsing frame at offset {offset} from {'client' if from_client else 'server'} buffer (Connection: {connection.client_addr} <-> {connection.server_addr}): {e}")
                # Attempt to find the next potential frame header for recovery
                recovery_offset = self.find_next_frame(current_buffer, offset + 1)
                if recovery_offset != -1:
                    logger.warning(f"Attempting to recover, skipping {recovery_offset - offset} bytes.")
                    offset = recovery_offset
                else:
                    logger.error(f"Failed to recover, stopping parsing for this buffer. Remaining unparseable: {len(current_buffer) - offset} bytes.")
                    offset = len(current_buffer) # Consume the rest of the buffer as unparseable
                    break # Cannot parse further from this point

        # Consume the parsed data from the buffer
        if offset > 0:
            if from_client:
                connection.client_buffer = current_buffer[offset:]
            else:
                connection.server_buffer = current_buffer[offset:]
        
        # If no frames were parsed (offset remains 0) but there's some data,
        # it means we're waiting for more bytes to form a complete frame header/body,
        # or the initial bytes are corrupted.
        if offset == 0 and len(current_buffer) > 0:
            logger.debug(f"Buffer for {'client' if from_client else 'server'} has {len(current_buffer)} bytes, waiting for more data to form a frame.")


    def _create_hyperframe_object(self, frame_type, flags, stream_id, body):
        """Helper to create the correct hyperframe object based on type."""
        try:
            if frame_type == 0x0:  # DATA
                frame = DataFrame(stream_id=stream_id)
            elif frame_type == 0x1:  # HEADERS
                frame = HeadersFrame(stream_id=stream_id)
            elif frame_type == 0x4:  # SETTINGS
                frame = SettingsFrame(stream_id=stream_id)
            elif frame_type == 0x8:  # WINDOW_UPDATE
                frame = WindowUpdateFrame(stream_id=stream_id)
            elif frame_type == 0x5: # PUSH_PROMISE
                frame = PushPromiseFrame(stream_id=stream_id)
            elif frame_type == 0x6: # PING
                frame = PingFrame(stream_id=stream_id)
            elif frame_type == 0x7: # GOAWAY
                frame = GoAwayFrame(stream_id=stream_id)
            elif frame_type == 0x3: # RST_STREAM
                frame = RstStreamFrame(stream_id=stream_id)
            elif frame_type == 0x2: # PRIORITY
                frame = PriorityFrame(stream_id=stream_id)
            else:
                logger.warning(f"Unsupported HTTP/2 frame type: {frame_type} (Stream ID: {stream_id})")
                # Return a generic frame for unsupported types to allow continuation
                class GenericFrame:
                    def __init__(self, frame_type, flags, stream_id, body):
                        self.type = frame_type
                        self.flags = flags
                        self.stream_id = stream_id
                        self.body = body
                return GenericFrame(frame_type, flags, stream_id, body)
            
            frame.flags = flags
            frame.body = body
            return frame
        except Exception as e:
            logger.error(f"Error creating hyperframe object for type {frame_type}: {e}")
            return None

    def _handle_connection_frame(self, frame, connection, from_client):
        """Handles HTTP/2 frames with Stream ID 0 (connection-level frames)."""
        if isinstance(frame, SettingsFrame):
            try:
                settings_list = []
                # Settings frame body consists of 6-byte pairs (ID, Value)
                for i in range(0, len(frame.body), 6):
                    setting_id = struct.unpack('>H', frame.body[i:i+2])[0]
                    value = struct.unpack('>I', frame.body[i+2:i+6])[0]
                    settings_list.append((setting_id, value))
                
                for setting_id, value in settings_list:
                    # Update HPACK decoder header table size based on SETTINGS_HEADER_TABLE_SIZE (0x1)
                    if setting_id == 0x1:
                        if from_client:
                            connection.client_hpack_decoder.header_table_size = value
                        else:
                            connection.server_hpack_decoder.header_table_size = value
                        connection.settings['SETTINGS_HEADER_TABLE_SIZE'] = value
                    elif setting_id == 0x2:
                        connection.settings['SETTINGS_ENABLE_PUSH'] = value
                    elif setting_id == 0x3:
                        connection.settings['SETTINGS_MAX_CONCURRENT_STREAMS'] = value
                    elif setting_id == 0x4:
                        connection.settings['SETTINGS_INITIAL_WINDOW_SIZE'] = value
                    elif setting_id == 0x5:
                        connection.settings['SETTINGS_MAX_FRAME_SIZE'] = value
                    elif setting_id == 0x6:
                        connection.settings['SETTINGS_MAX_HEADER_LIST_SIZE'] = value
                    logger.debug(f"Connection SETTINGS update: ID {setting_id} = {value}")
            except Exception as e:
                logger.error(f"Error processing SETTINGS frame: {e}")
        elif isinstance(frame, PingFrame):
            logger.debug(f"Received PING frame from {'client' if from_client else 'server'} (ACK: {bool(frame.flags & 0x1)})")
        elif isinstance(frame, GoAwayFrame):
            # GOAWAY frame indicates connection termination or graceful shutdown
            error_code = struct.unpack('>I', frame.body[4:8])[0] if len(frame.body) >= 8 else 0
            logger.info(f"Received GOAWAY frame from {'client' if from_client else 'server'}. Last Stream ID: {frame.stream_id}, Error Code: {error_code}")
        else:
            logger.debug(f"Unhandled connection-level frame type: {frame.type} from {'client' if from_client else 'server'}")

    def handle_frame(self, frame, stream, connection, from_client):
        """
        Handles a stream-specific HTTP/2 frame, adding its data to the appropriate stream.
        Triggers logging when a server response is complete.
        """
        try:
            # Store the server_complete state *before* processing the current frame
            server_complete_before_current_frame = stream.server_complete 
            
            if isinstance(frame, HeadersFrame):
                headers = connection.decode_headers(frame.body, from_client)
                end_stream = bool(frame.flags & 0x1) # END_STREAM flag (0x1)
                stream.add_headers(headers, from_client, end_stream)
            elif isinstance(frame, DataFrame):
                end_stream = bool(frame.flags & 0x1) # END_STREAM flag (0x1)
                stream.add_data(frame.body, from_client, end_stream)
            elif isinstance(frame, PushPromiseFrame):
                # PUSH_PROMISE is always from server to client
                promised_stream_id = struct.unpack('>I', frame.body[:4])[0] & 0x7FFFFFFF
                headers = connection.decode_headers(frame.body[4:], from_client=False) # Headers are from server's perspective
                if promised_stream_id not in connection.streams:
                    connection.streams[promised_stream_id] = HTTP2Stream(promised_stream_id)
                # For push promise, the headers describe the *promised request* from the server's perspective,
                # so they are added as client headers to the new stream.
                connection.streams[promised_stream_id].add_headers(headers, from_client=True, end_stream=False) 
                logger.info(f"Stream {stream.stream_id}: PUSH_PROMISE for new stream {promised_stream_id}")
            elif isinstance(frame, WindowUpdateFrame):
                logger.debug(f"Stream {stream.stream_id}: WINDOW_UPDATE ({frame.body.hex()}) from {'client' if from_client else 'server'}")
            elif isinstance(frame, RstStreamFrame):
                # RST_STREAM indicates an abrupt termination of a stream
                error_code = struct.unpack('>I', frame.body)[0]
                logger.info(f"Stream {stream.stream_id}: RST_STREAM (Error Code: {error_code}) from {'client' if from_client else 'server'}")
                # A RST_STREAM implies the stream is complete (terminated) from the sender's perspective
                if from_client:
                    stream.client_complete = True
                else:
                    stream.server_complete = True
            elif isinstance(frame, PriorityFrame):
                logger.debug(f"Stream {stream.stream_id}: PRIORITY ({frame.body.hex()}) from {'client' if from_client else 'server'}")
            else:
                logger.debug(f"Stream {stream.stream_id}: Unhandled frame type {frame.type} from {'client' if from_client else 'server'}")

        except Exception as e:
            logger.error(f"Error handling frame for stream {stream.stream_id}: {e}")

    def find_next_frame(self, data, start_offset):
        """
        Attempts to find the start of the next potential HTTP/2 frame header
        after an error or incomplete data. This is a heuristic for recovery.
        """
        # Iterate through the data from start_offset, looking for a plausible frame header
        for i in range(start_offset, len(data) - 9):
            try:
                # Attempt to unpack length (3 bytes) and type (1 byte)
                length = struct.unpack('>I', b'\x00' + data[i:i+3])[0]
                frame_type = data[i+3]
                
                # Basic sanity checks for a plausible frame header:
                # 1. Length should be a valid 24-bit value (0 to 2^24-1).
                # 2. Frame type should be within known standard types (0x0 to 0x9).
                # 3. The full frame (header + body) must fit within the remaining data.
                if (0 <= length <= 16777215 and 
                    0 <= frame_type <= 0x9 and 
                    i + 9 + length <= len(data)):
                    logger.debug(f"Found potential next frame header at offset {i} (type: {frame_type}, length: {length})")
                    return i # Return the offset where a potential frame starts
            except struct.error:
                continue # Not a valid header start, continue searching
            except IndexError:
                break # Reached end of data while trying to read header
        logger.debug(f"No next potential frame header found from offset {start_offset}")
        return -1 # No plausible frame found
