# Import specific frame types from hyperframe
from .utils import logger

class HTTP2Stream:
    """
    Represents an HTTP/2 stream, accumulating headers and data for both client and server sides.
    """
    def __init__(self, stream_id):
        """
        Initialize a new HTTP2Stream instance with the specified stream ID.
        
        Sets up separate storage for client and server headers, data, and trailers, as well as flags to track stream completion and response logging status.
        """
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
        """
        Adds headers or trailers to the client or server side of the HTTP/2 stream.
        
        If headers are added after the initial headers frame, they are treated as trailers. Marks the respective side as complete if `end_stream` is True.
        
        Parameters:
            headers (list): The list of header tuples to add.
            from_client (bool): If True, adds headers to the client side; otherwise, to the server side.
            end_stream (bool, optional): If True, marks the stream as complete for the respective side. Defaults to False.
        """
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
        """
        Appends data bytes to either the client or server side of the stream.
        
        Parameters:
            data (bytes): The data to append.
            from_client (bool): If True, data is added to the client side; otherwise, to the server side.
            end_stream (bool, optional): If True, marks the respective side as complete after adding the data.
        """
        if from_client:
            self.client_data += data
            if end_stream:
                self.client_complete = True
        else:
            self.server_data += data
            if end_stream:
                self.server_complete = True

    def get_request_method(self):
        """
        Return the HTTP request method from the client headers if present.
        
        Returns:
            str or None: The value of the ':method' pseudo-header, or None if not found.
        """
        for name, value in self.client_headers:
            if name == ':method':
                return value
        return None

    def get_request_path(self):
        """
        Return the HTTP/2 request path from the client headers, or None if not present.
        
        Returns:
            str or None: The value of the ':path' pseudo-header if found, otherwise None.
        """
        for name, value in self.client_headers:
            if name == ':path':
                return value
        return None

    def get_response_status(self):
        """
        Return the HTTP/2 response status code from the server headers.
        
        Returns:
            str or None: The value of the ':status' pseudo-header if present; otherwise, None.
        """
        for name, value in self.server_headers:
            if name == ':status':
                return value
        return None