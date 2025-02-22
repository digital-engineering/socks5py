import logging
import select
import socket
import struct
import sys

from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from typing import Callable, Literal

from soxprox.enum import AddressDataType, AuthMethod, StatusCode
from soxprox.pool import IpAddressProxyPool


class SOCKS5Proxy(ThreadingMixIn, TCPServer):
    """SOCKS5 TCP socket server."""
    BIND_PORT = 0  # set to 0 if we are binding an address, lets the kernel decide a free port
    allow_reuse_address = True

    def __init__(self, host_port: tuple[str, int], options: dict | None = None):
        options = options or {}
        # Check types, if the options are valid
        if 'auth' in options:
            if not isinstance(options['auth'], tuple):
                logging.error("Auth must be a tuple with 2 items (username, password) or not set")
                sys.exit()

            if len(options['auth']) != 2:
                logging.error("Auth must be a tuple with 2 items (username, password)")
                sys.exit()

            for item in options['auth']:
                if not isinstance(item, str):
                    logging.error("Tuple item must be a string (type str)")
                    sys.exit()

            self._auth = options['auth']

        if 'bind_address' in options:
            # This should error out if invalid
            # This allows us to parse the address given by a user on the start of the server
            bind_addr_info = socket.getaddrinfo(
                options['bind_address'], self.BIND_PORT, family=socket.AF_UNSPEC,
                type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
            if len(bind_addr_info) > 0:
                self._bind = bind_addr_info[0][4]  # Is picking first a good idea?
            else:
                logging.error("Failed to resolve bind address")
                sys.exit()

        self.address_family = socket.AF_INET6 if ':' in host_port[0] else socket.AF_INET

        super().__init__(host_port, ProxyRequestHandler)


class ProxyRequestHandler(StreamRequestHandler):
    # Constants
    CONNECT = 1
    CONNECTION_TIMEOUT = 60 * 15 * 1000
    FAILURE = 0xFF
    RESERVED = 0
    SOCKS_VERSION = 5
    USERNAME_PASSWORD_VERSION = 1

    # Buffer sizes
    CONN_NO_PORT_SIZE = 4
    CONN_PORT_SIZE = 2
    COPY_LOOP_BUFFER_SIZE = 4096
    DOMAIN_SIZE = 1
    GREETING_SIZE = 2
    ID_LEN_SIZE = 1
    PW_LEN_SIZE = 1
    VERSION_SIZE = 1

    username = 'username'
    password = 'password'

    logger: logging.Logger
    proxy_pool: IpAddressProxyPool

    def handle(self) -> None:
        """
        Handle the connection.

        Forward the client's request to the destination via a randomly chosen IPv6 address.
        """
        client_ip, client_port, *_ = self.client_address
        self.logger.info(f'Accepting connection from [{client_ip}]:{client_port}')

        self._auth_client()
        address_type, address = self._handle_client_request()
        response_data = self._get_response_data(client_ip, address_type, address)

        # Send the response data to the client
        self._send(response_data)

        # Run the copy loop
        self._copy_loop(self.request, self._remote)
        self._exit(True)

    @property
    def auth_method(self):
        """Gives us the authentication method we will use"""
        return AuthMethod.UsernamePassword if hasattr(self.server, '_auth') else AuthMethod.NoAuth

    def get_available_methods(self, n: int) -> list:
        methods = []
        for _ in range(n):
            methods.append(ord(self.connection.recv(1)))

        return methods

    def verify_credentials(self) -> bool:
        version = ord(self.connection.recv(1))
        assert version == 1

        username_len = ord(self.connection.recv(1))
        username = self.connection.recv(username_len).decode('utf-8')

        password_len = ord(self.connection.recv(1))
        password = self.connection.recv(password_len).decode('utf-8')

        if username == self.username and password == self.password:
            # success, status = 0
            response = struct.pack("!BB", version, 0)
            self.connection.sendall(response)
            return True

        # failure, status != 0
        response = struct.pack("!BB", version, 0xFF)
        self.connection.sendall(response)
        self.server.close_request(self.request)
        return False

    def generate_failed_reply(self, address_type, error_number) -> bytes:
        return struct.pack("!BBBBIH", self.SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote) -> None:
        while True:
            # wait until client or remote is available for read
            r, w, e = select.select([client, remote], [], [])

            if client in r:
                try:
                    data = client.recv(4096)
                except ConnectionResetError:
                    break
                if remote.send(data) <= 0:
                    break

            if remote in r:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

    def _auth_client(self) -> None:
        # greeting header
        # read and unpack 2 bytes from a client
        # header = self.connection.recv(2)
        header = self._recv(self.GREETING_SIZE, self._send_greeting_failure, AuthMethod.Invalid)
        version, n_methods = struct.unpack("!BB", header)

        # Only accept SOCKS5
        if version != self.SOCKS_VERSION:
            self._send_greeting_failure(self.auth_method)

        # We need at least one method
        if n_methods < 1:
            self._send_greeting_failure(AuthMethod.Invalid)

        # get available methods
        methods = self.get_available_methods(n_methods)

        # Accept only USERNAME/PASSWORD auth if we are asking for auth
        # Accept only no auth if we are not asking for USERNAME/PASSWORD
        if (self.auth_method and AuthMethod.UsernamePassword not in set(methods)) or (
                not self.auth_method and AuthMethod.NoAuth not in set(methods)):
            self._send_greeting_failure(AuthMethod.Invalid)

        # Choose an authentication method and send it to the client
        self._send(struct.pack("!BB", self.SOCKS_VERSION, self.auth_method))

        # If we are asking for USERNAME/PASSWORD auth verify it
        if self.auth_method:
            self._verify_credentials()

        # Auth/greeting handled...
        self.logger.debug("Successfully authenticated")

    def _copy_loop(self, client, remote) -> None:
        """Waits for network activity and forwards it to the other connection"""
        while True:
            # Wait until client or remote is available for read
            #
            # Alternatively use poll() instead of select() due to these reasons
            # https://github.com/rofl0r/microsocks/commit/31557857ccce5e4fdd2cfdae7ab640d589aa2b41
            # May not be ideal for a cross platform implementation however
            r, w, e = select.select([client, remote], [], [], self.CONNECTION_TIMEOUT)

            # Kill inactive/unused connections
            if not r and not w and not e:
                self._send_failure(StatusCode.TTLExpired)

            for sock in r:
                try:
                    data = sock.recv(self.COPY_LOOP_BUFFER_SIZE)
                except Exception as err:
                    self.logger.debug("Copy loop failed to read")
                    self.logger.error(err)
                    return

                if not data or len(data) <= 0:
                    return

                outfd = remote if sock is client else client
                try:
                    outfd.sendall(data)  # Python has its own sendall implemented
                except Exception as err:
                    self.logger.debug("Copy loop failed to send all data")
                    self.logger.error(err)
                    return

    def _exit(self, dontExit: bool = False) -> None:
        """Exit the thread and cleanup any connections."""
        self._shutdown_client()
        if hasattr(self, "_remote"):
            # self._remote.shutdown(socket.SHUT_RDWR)
            self._remote.close()

        if not dontExit:
            sys.exit()

    def _get_response_data(self, client_ip: str, address_type: int, address: str):
        port_buffer = self._recv(
            self.CONN_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure)
        port = struct.unpack('!H', port_buffer)[0]

        # Translate our address and port into data from which we can create a socket connection
        try:
            remote_info = socket.getaddrinfo(
                address, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
            # Pick the first one returned, probably IPv6 if IPv6 is available or IPv4 if not
            # TO-DO: Try as many as possible in a loop instead of picking only the first returned
            test_af = socket.AF_INET6 if ':' in client_ip else socket.AF_INET
            remote_info = filtered[0] if (
                filtered := [info for info in remote_info if info[0] == test_af]
            ) else remote_info[0]

        except Exception as err:  # There's no suitable errorcode in RFC1928 for DNS lookup failure
            self.logger.error(err)
            self._send_failure(StatusCode.GeneralFailure)

        af, socktype, proto, _, sa = remote_info
        assert af in (socket.AF_INET, socket.AF_INET6)
        assert isinstance(socktype, int)
        assert isinstance(proto, int)

        # Connect to the socket
        try:
            # Make the socket
            self._remote = socket.socket(af, socktype, proto)
            if hasattr(self.server, '_bind'):
                self._remote.bind(self.server._bind)  # type: ignore
            elif af == socket.AF_INET6:  # Bind it to a random IPv6 IP from the pool
                assert isinstance(self.proxy_pool, IpAddressProxyPool)
                ipv6_address = self.proxy_pool.get_random_address()
                self._remote.bind((ipv6_address, 0, 0, 0))

            self._remote.connect(sa)
            bind_address = self._remote.getsockname()
            self.logger.info(f'Connected to {address} {port}')

            # Get the bind address and port
            # Check if the address is IPv4 or IPv6
            bind_port = bind_address[1]
            if ':' in bind_address[0]:  # IPv6
                addr = struct.unpack("!IIII", socket.inet_pton(socket.AF_INET6, bind_address[0]))
            else:  # IPv4
                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            self.logger.debug(f'Bind address {addr} {bind_port}')
        except Exception as err:
            self.logger.error(err)
            # TO-DO: Get the actual failure code instead of giving ConnRefused each time
            self._send_failure(StatusCode.ConnRefused)

        # if Address type is domain, convert to IPv4 or IPv6 for response data
        if address_type == AddressDataType.DomainName:
            if af == socket.AF_INET:
                address_type = AddressDataType.IPv4
            else:
                address_type = AddressDataType.IPv6

        # TO-DO: Are the BND.ADDR and BND.PORT returned correct values?
        # Check if the address type is IPv4 or IPv6 and pack the response data accordingly
        if address_type == AddressDataType.IPv4:
            response_data = struct.pack(
                "!BBBBIH", self.SOCKS_VERSION, StatusCode.Success, self.RESERVED, address_type, addr, bind_port)
        elif address_type == AddressDataType.IPv6:
            response_data = struct.pack(
                "!BBBBIIIIH", self.SOCKS_VERSION, StatusCode.Success, self.RESERVED, address_type, *addr, bind_port)

        return response_data

    def _handle_client_request(self) -> tuple:
        version, cmd, rsv, address_type = struct.unpack("!BBBB", self._recv(
            self.CONN_NO_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure
        ))

        # Do this so we can send an address_type in our errors
        # We don't want to send an invalid one back in an error so we will
        # handle an invalid address type first
        # microsocks just always sends IPv4 instead
        if address_type in [AddressDataType.IPv4, AddressDataType.IPv6, AddressDataType.DomainName]:
            self._address_type = address_type
        else:
            self._send_failure(StatusCode.AddressTypeNotSupported)

        if version != self.SOCKS_VERSION:
            self._send_failure(StatusCode.GeneralFailure)
        if cmd != self.CONNECT:  # We only support connect
            self._send_failure(StatusCode.CommandNotSupported)
        if rsv != self.RESERVED:  # Malformed packet
            self._send_failure(StatusCode.GeneralFailure)

        self.logger.debug(f'Handling request with address type: {address_type}')

        if address_type == AddressDataType.IPv4 or address_type == AddressDataType.IPv6:
            address_family = (
                socket.AF_INET if address_type == AddressDataType.IPv4 else socket.AF_INET6)

            minlen = 4 if address_type == AddressDataType.IPv4 else 16
            # Raw IP address bytes
            raw = self._recv(minlen, self._send_failure, StatusCode.GeneralFailure)

            # Convert the IP address from binary to text
            try:
                address = socket.inet_ntop(address_family, raw)
            except Exception as err:
                self.logger.debug(f'Could not convert packed IP {raw} to string')
                self.logger.error(err)
                self._send_failure(StatusCode.GeneralFailure)

        elif address_type == AddressDataType.DomainName:  # Domain name
            domain_buffer = self._recv(
                self.DOMAIN_SIZE, self._send_failure, StatusCode.GeneralFailure)
            domain_length = domain_buffer[0]
            if domain_length > 255:  # Invalid
                self._send_failure(StatusCode.GeneralFailure)

            address = self._recv(domain_length, self._send_failure, StatusCode.GeneralFailure)

        return address_type, address

    def _recv(
        self,
        bufsize,
        failure_method: Callable | Literal[False] = False,
        code: int | Literal[False] = False
    ):
        """
        Receive bytes from a client.

        If bufsize is less than the size of the data received, then 
        failure_method is called with code as a parameter and kills the thread.
        """
        buf = self.request.recv(bufsize)
        if len(buf) < bufsize:
            if failure_method and code:
                failure_method(code)
            elif failure_method:
                failure_method()
            else:
                self._exit()  # Kill thread if we aren't calling the failure methods (they already do this)

        return buf

    def _send(self, data):
        """Send bytes to a client"""
        return self.request.sendall(data)

    def _send_authentication_failure(self, code) -> None:
        """Send a failure message to a client in the authentication stage"""
        self._send(struct.pack("!BB", self.USERNAME_PASSWORD_VERSION, code))
        self._exit()

    def _send_failure(self, code) -> None:
        """Send a failure message to a client in the socket stage"""
        a_type = self._address_type if hasattr(self, "_address_type") else AddressDataType.IPv4
        self._send(struct.pack("!BBBBIH", self.SOCKS_VERSION, code, self.RESERVED, a_type, 0, 0))
        self._exit()

    def _send_greeting_failure(self, code) -> None:
        """Send a failure message to a client in the greeting stage"""
        self._send(struct.pack("!BB", self.SOCKS_VERSION, code))
        self._exit()

    def _shutdown_client(self) -> None:
        """Shutdown and close the connection with a client"""
        self.server.shutdown_request(self.request)

    def _verify_credentials(self) -> bool | None:
        """
        Verify the credentials of a client and send a response relevant response.
        Close the connection & thread if unauthenticated.
        """
        version = ord(self._recv(self.VERSION_SIZE))
        if version != self.USERNAME_PASSWORD_VERSION:
            self.logger.error(f'USERNAME_PASSWORD_VERSION did not match')
            self._send_authentication_failure(self.FAILURE)

        un_len = self._recv(self.ID_LEN_SIZE, self._send_authentication_failure, self.FAILURE)
        username = self._recv(ord(un_len), self._send_authentication_failure, self.FAILURE)

        pw_len = self._recv(self.PW_LEN_SIZE, self._send_authentication_failure, self.FAILURE)
        password = self._recv(ord(pw_len), self._send_authentication_failure, self.FAILURE)

        server_username, server_password = self.server._auth  # type: ignore

        if username.decode('utf-8') == server_username and password.decode('utf-8') == server_password:
            self._send(struct.pack("!BB", self.USERNAME_PASSWORD_VERSION, StatusCode.Success))
            return True

        self.logger.error(f'Authentication failed')
        self._send_authentication_failure(self.FAILURE)
