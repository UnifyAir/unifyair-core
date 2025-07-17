
# Import specific frame types from hyperframe
from .utils import logger

class HTTP2Stream:
    """
    Represents an HTTP/2 stream, accumulating headers and data for both client and server sides.
    """
    def __init__(self, stream_id):
        self.stream_id = stream_id
        self.client_headers = []
        self.client_data = b''
        self.client_trailers = []
        self.client_complete = False
        self.server_headers = []
        self.server_data = b''
        self.server_trailers = []
        self.server_complete = False
        self.state = 'idle' # Not extensively used for state machine logic in this version
        self.response_logged = False  # Flag to avoid duplicate logging of a completed response

    def add_headers(self, headers, from_client, end_stream=False):
        """Adds headers to the appropriate side of the stream."""
        if from_client:
            if not self.client_headers:
                self.client_headers = headers
            else:
                self.client_trailers = headers # Subsequent HEADERS frames are trailers
            if end_stream:
                self.client_complete = True
        else:
            if not self.server_headers:
                self.server_headers = headers
            else:
                self.server_trailers = headers # Subsequent HEADERS frames are trailers
            if end_stream:
                self.server_complete = True

    def add_data(self, data, from_client, end_stream=False):
        """Adds data to the appropriate side of the stream."""
        if from_client:
            self.client_data += data
            if end_stream:
                self.client_complete = True
        else:
            self.server_data += data
            if end_stream:
                self.server_complete = True

    def get_request_method(self):
        """Extracts the HTTP request method from client headers."""
        for name, value in self.client_headers:
            if name == ':method':
                return value
        return None

    def get_request_path(self):
        """Extracts the HTTP request path from client headers."""
        for name, value in self.client_headers:
            if name == ':path':
                return value
        return None

    def get_response_status(self):
        """Extracts the HTTP response status from server headers."""
        for name, value in self.server_headers:
            if name == ':status':
                return value
        return None