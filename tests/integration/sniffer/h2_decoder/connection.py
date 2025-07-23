from .utils import logger
from hpack import Decoder

class HTTP2Connection:
    """
    Manages HTTP/2 connection state and HPACK context for both directions (client and server).
    """
    def __init__(self, client_addr, server_addr):
        """
        Initialize an HTTP2Connection instance with client and server addresses, HPACK decoders, connection settings, and buffers for bidirectional data.
        
        Parameters:
            client_addr (tuple): The (IP, port) tuple identifying the HTTP/2 client.
            server_addr (tuple): The (IP, port) tuple identifying the HTTP/2 server.
        """
        self.client_addr = client_addr  # (ip, port) of the HTTP/2 client
        self.server_addr = server_addr  # (ip, port) of the HTTP/2 server
        self.client_hpack_decoder = Decoder()
        self.server_hpack_decoder = Decoder()
        self.streams = {}  # stream_id -> HTTP2Stream
        self.settings = {
            'SETTINGS_HEADER_TABLE_SIZE': 4096,
            'SETTINGS_ENABLE_PUSH': 1,
            'SETTINGS_MAX_CONCURRENT_STREAMS': None,
            'SETTINGS_INITIAL_WINDOW_SIZE': 65535,
            'SETTINGS_MAX_FRAME_SIZE': 16384,
            'SETTINGS_MAX_HEADER_LIST_SIZE': None
        }
        self.preface_seen = False # True once the HTTP/2 preface is detected for this connection
        
        # Buffers for incremental parsing for each direction
        self.client_buffer = b'' # Data from client_addr to server_addr
        self.server_buffer = b'' # Data from server_addr to client_addr

    def decode_headers(self, headers_data, from_client):
        """
        Decodes HPACK-compressed HTTP/2 headers using the appropriate decoder for client or server direction.
        
        Parameters:
            headers_data (bytes): HPACK-compressed header block to decode.
            from_client (bool): If True, decodes using the client HPACK decoder; otherwise, uses the server decoder.
        
        Returns:
            list: A list of (name, value) tuples representing decoded HTTP/2 headers as UTF-8 strings. Returns an empty list if decoding fails.
        """
        try:
            decoder = self.client_hpack_decoder if from_client else self.server_hpack_decoder
            headers = decoder.decode(headers_data)
            decoded_headers = []
            for name, value in headers:
                if isinstance(name, bytes):
                    name = name.decode('utf-8', errors='replace')
                if isinstance(value, bytes):
                    value = value.decode('utf-8', errors='replace')
                decoded_headers.append((name, value))
            return decoded_headers
        except Exception as e:
            logger.error(f"Error decoding headers: {e}")
            return []