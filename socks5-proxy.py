#!/usr/bin/env python3
import ipaddress
import logging
import psutil
import random
import select
import socket
import struct
import subprocess
import sys

from socketserver import ThreadingMixIn, TCPServer, StreamRequestHandler
from typing import Callable, Literal

logging.basicConfig(level=logging.DEBUG)

# Constants
BIND_PORT = 0  # set to 0 if we are binding an address, lets the kernel decide a free port
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


class AddressDataType:
    IPv4 = 1
    DomainName = 3
    IPv6 = 4


class AuthMethod:
    NoAuth = 0
    GSSAPI = 1
    UsernamePassword = 2
    Invalid = 0xFF


class StatusCode:
    Success = 0
    GeneralFailure = 1
    NotAllowed = 2
    NetUnreachable = 3
    HostUnreachable = 4
    ConnRefused = 5
    TTLExpired = 6
    CommandNotSupported = 7
    AddressTypeNotSupported = 8


class Ipv6AddressProxyPool:
    INTERFACE = 'eth0'

    def __init__(self, n_ips: int = 8):
        self.__default_address_int = 0
        self.__hostmask_int = 0
        self.__logger = logging.getLogger(__name__)
        self.__n_ips = n_ips

    def __enter__(self) -> 'Ipv6AddressProxyPool':
        try:
            default_ip_masked = sorted(
                self.find_ipv6_addresses(True),
                key=lambda address: int(ipaddress.IPv6Address(address.split('/')[0]))
            )[0]  # Assume lowest IPv6 address is the default ip
            default_ip = default_ip_masked.split('/')[0]
        except IndexError:
            raise RuntimeError('No IPv6 address found.')

        default_ip_address = ipaddress.IPv6Address(default_ip)
        public_network = ipaddress.IPv6Network(default_ip_masked, strict=False)
        if public_network.network_address > default_ip_address:
            raise RuntimeError(
                'Public network address {} is higher than default ip address. {}'.format(
                    str(public_network.network_address),
                    default_ip))

        self.__default_address_int = int(default_ip_address)
        self.__hostmask_int = int(public_network.hostmask)
        self.addresses = []
        for _ in range(self.__n_ips):
            self.addresses.append(self.create_ipv6_address())

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.shutdown()

    def create_ipv6_address(self) -> str:
        """Create a new IPv6 address."""
        ipv6_address = str(ipaddress.IPv6Address(random.randint(
            self.__default_address_int + 1,
            self.__default_address_int + self.__hostmask_int - 1
        )))

        # create IPv6 address
        result = subprocess.run(
            ['sudo', 'ip', '-6', 'addr', 'add', str(ipv6_address), 'dev', self.INTERFACE],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            raise RuntimeError(f'Failed to create IPv6 address: {result.stdout}\n{result.stderr}')

        return ipv6_address

    def get_random_ipv6_address(self) -> str:
        """Get a random IPv6 address from the pool."""
        return random.choice(self.addresses)

    def find_ipv6_addresses(self, append_mask: bool = False) -> list[str]:
        """Find all IPv6 addresses on the interface.

        Given all IPv6 addresses on the interface specified in self.INTERFACE,
        (eth0 by default) return a list of public IPv6 addresses on that interface.

        Args:
            append_mask (bool, optional): If True, will append the CIDR bitmask. [default: False]

        Returns:
            list[str]: List of public IPv6 addresses on the interface.
        """
        return [
            (f'{address}/{self.__netmask_to_cidr(str(snic.netmask))}'
             if (address := snic.address.replace(f'%{self.INTERFACE}', ''))
             and append_mask
             else address)
            for snic in (psutil.net_if_addrs().get(self.INTERFACE) or [])
            if snic.family == socket.AF_INET6
            and ipaddress.IPv6Address(snic.address).is_global
        ]

    def shutdown(self) -> None:
        """Remove all ipv6 addresses."""
        for address in self.find_ipv6_addresses():
            if int(ipaddress.IPv6Address(address)) == self.__default_address_int:
                continue  # DON'T remove the origin public IPv6 address

            result = subprocess.run(
                ['sudo', 'ip', '-6', 'addr', 'del', address, 'dev', self.INTERFACE],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                self.__logger.error(
                    f'Failed to remove IPv6 address: {result.stdout}\n{result.stderr}')

    def __netmask_to_cidr(self, netmask: str) -> int:
        """Convert psutil.net_if_addrs().netmask to CIDR notation."""
        HEX_BASE = 16

        # Convert the netmask to binary string
        binary = bin(int(netmask.replace(':', ''), HEX_BASE))

        # Count the number of 1 bits
        return binary.count('1')


class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    """Just the server which will process a dictionary of options and initialise the socket server"""
    address_family = socket.AF_INET6
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
                options['bind_address'], BIND_PORT, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
            if len(bind_addr_info) > 0:
                self._bind = bind_addr_info[0][4]  # Is picking first a good idea?
            else:
                logging.error("Failed to resolve bind address")
                sys.exit()

        super().__init__(host_port, ProxyRequestHandler)


class ProxyRequestHandler(StreamRequestHandler):
    username = 'username'
    password = 'password'
    proxy_pool: Ipv6AddressProxyPool | None = None

    def handle(self):
        """
        Handle the connection.

        Forward the client's request to the destination via a randomly chosen IPv6 address.
        """
        ip, port, *_ = self.client_address
        logging.info(f'Accepting connection from [{ip}]:{port}')

        # greeting header
        # read and unpack 2 bytes from a client
        # header = self.connection.recv(2)
        header = self._recv(GREETING_SIZE, self._send_greeting_failure, AuthMethod.Invalid)
        version, n_methods = struct.unpack("!BB", header)

        # Only accept SOCKS5
        if version != SOCKS_VERSION:
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
        self._send(struct.pack("!BB", SOCKS_VERSION, self.auth_method))

        # If we are asking for USERNAME/PASSWORD auth verify it
        if self.auth_method:
            self._verify_credentials()

        # Auth/greeting handled...
        logging.debug("Successfully authenticated")

        # Handle the request
        conn_buffer = self._recv(CONN_NO_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure)
        version, cmd, rsv, address_type = struct.unpack("!BBBB", conn_buffer)
        # Do this so we can send an address_type in our errors
        # We don't want to send an invalid one back in an error so we will handle an invalid address
        # type first
        # Microsocks just always sends IPv4 instead
        if address_type in [AddressDataType.IPv4, AddressDataType.IPv6, AddressDataType.DomainName]:
            self._address_type = address_type
        else:
            self._send_failure(StatusCode.AddressTypeNotSupported)

        if version != SOCKS_VERSION:
            self._send_failure(StatusCode.GeneralFailure)
        if cmd != CONNECT:  # We only support connect
            self._send_failure(StatusCode.CommandNotSupported)
        if rsv != RESERVED:  # Malformed packet
            self._send_failure(StatusCode.GeneralFailure)

        logging.debug(f'Handling request with address type: {address_type}')

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
                logging.debug(f'Could not convert packed IP {raw} to string')
                logging.error(err)
                self._send_failure(StatusCode.GeneralFailure)

        elif address_type == AddressDataType.DomainName:  # Domain name
            domain_buffer = self._recv(DOMAIN_SIZE, self._send_failure, StatusCode.GeneralFailure)
            domain_length = domain_buffer[0]
            if domain_length > 255:  # Invalid
                self._send_failure(StatusCode.GeneralFailure)

            address = self._recv(domain_length, self._send_failure, StatusCode.GeneralFailure)

        port_buffer = self._recv(CONN_PORT_SIZE, self._send_failure, StatusCode.GeneralFailure)
        port = struct.unpack('!H', port_buffer)[0]

        # Translate our address and port into data from which we can create a socket connection
        try:
            remote_info = socket.getaddrinfo(
                address, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM, flags=socket.AI_PASSIVE)
            # Pick the first one returned, probably IPv6 if IPv6 is available or IPv4 if not
            # TO-DO: Try as many as possible in a loop instead of picking only the first returned
            remote_info = remote_info[0]
        except Exception as err:  # There's no suitable errorcode in RFC1928 for DNS lookup failure
            logging.error(err)
            self._send_failure(StatusCode.GeneralFailure)

        af, socktype, proto, _, sa = remote_info

        # assert isinstance(self.proxy_pool, Ipv6AddressProxyPool)
        # ipv6_address = self.proxy_pool.get_random_ipv6_address()

        # Connect to the socket
        try:
            # Make the socket
            self._remote = socket.socket(af, socktype, proto)
            # Bind it to an IP
            if hasattr(self.server, '_bind'):
                self._remote.bind(self.server._bind)  # type: ignore
            self._remote.connect(sa)
            bind_address = self._remote.getsockname()
            logging.info(f'Connected to {address} {port}')

            # Get the bind address and port
            # Check if the address is IPv4 or IPv6
            if ':' in bind_address[0]:  # IPv6
                addr = struct.unpack("!IIII", socket.inet_pton(socket.AF_INET6, bind_address[0]))
            else:  # IPv4
                addr = struct.unpack("!I", socket.inet_aton(bind_address[0]))[0]
            port = bind_address[1]
            logging.debug(f'Bind address {addr} {port}')
        except Exception as err:
            logging.error(err)
            # TO-DO: Get the actual failure code instead of giving ConnRefused each time
            self._send_failure(StatusCode.ConnRefused)

        # TO-DO: Are the BND.ADDR and BND.PORT returned correct values?
        # Check if the address type is IPv4 or IPv6 and pack the response data accordingly
        if address_type == AddressDataType.IPv4:
            response_data = struct.pack(
                "!BBBBIH", SOCKS_VERSION, StatusCode.Success, RESERVED, address_type, addr, port)
        elif address_type == AddressDataType.IPv6:
            response_data = struct.pack(
                "!BBBBIIIIH", SOCKS_VERSION, StatusCode.Success, RESERVED, address_type, *addr, port)

        self._send(response_data)

        # Run the copy loop
        self._copy_loop(self.request, self._remote)
        self._exit(True)

    @property
    def auth_method(self):
        """Gives us the authentication method we will use"""
        return AuthMethod.UsernamePassword if hasattr(self.server, '_auth') else AuthMethod.NoAuth

    def get_available_methods(self, n):
        methods = []
        for _ in range(n):
            methods.append(ord(self.connection.recv(1)))
        return methods

    def verify_credentials(self):
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

    def generate_failed_reply(self, address_type, error_number):
        return struct.pack("!BBBBIH", SOCKS_VERSION, error_number, 0, address_type, 0, 0)

    def exchange_loop(self, client, remote):
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

    def _copy_loop(self, client, remote):
        """Waits for network activity and forwards it to the other connection"""
        while True:
            # Wait until client or remote is available for read
            #
            # Alternatively use poll() instead of select() due to these reasons
            # https://github.com/rofl0r/microsocks/commit/31557857ccce5e4fdd2cfdae7ab640d589aa2b41
            # May not be ideal for a cross platform implementation however
            r, w, e = select.select([client, remote], [], [], CONNECTION_TIMEOUT)

            # Kill inactive/unused connections
            if not r and not w and not e:
                self._send_failure(StatusCode.TTLExpired)

            for sock in r:
                try:
                    data = sock.recv(COPY_LOOP_BUFFER_SIZE)
                except Exception as err:
                    logging.debug("Copy loop failed to read")
                    logging.error(err)
                    return

                if not data or len(data) <= 0:
                    return

                outfd = remote if sock is client else client
                try:
                    outfd.sendall(data)  # Python has its own sendall implemented
                except Exception as err:
                    logging.debug("Copy loop failed to send all data")
                    logging.error(err)
                    return

    def _exit(self, dontExit=False):
        """Convenience method to exit the thread and cleanup any connections"""
        self._shutdown_client()
        if hasattr(self, "_remote"):
            # self._remote.shutdown(socket.SHUT_RDWR)
            self._remote.close()

        if not dontExit:
            sys.exit()

    def _recv(
        self,
        bufsize,
        failure_method: Callable | Literal[False] = False,
        code: int | Literal[False] = False
    ):
        """
        Convenience method to receive bytes from a client.

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
        """Convenience method to send bytes to a client"""
        return self.request.sendall(data)

    def _send_authentication_failure(self, code):
        """Convinence method to send a failure message to a client in the authentication stage"""
        self._send(struct.pack("!BB", USERNAME_PASSWORD_VERSION, code))
        self._exit()

    def _send_failure(self, code):
        """Convinence method to send a failure message to a client in the socket stage"""
        address_type = self._address_type if hasattr(
            self, "_address_type") else AddressDataType.IPv4
        self._send(struct.pack("!BBBBIH", SOCKS_VERSION, code, RESERVED, address_type, 0, 0))
        self._exit()

    def _send_greeting_failure(self, code):
        """Convinence method to send a failure message to a client in the greeting stage"""
        self._send(struct.pack("!BB", SOCKS_VERSION, code))
        self._exit()

    def _shutdown_client(self):
        """Convenience method to shutdown and close the connection with a client"""
        self.server.shutdown_request(self.request)

    def _verify_credentials(self):
        """Verify the credentials of a client and send a response relevant response
            and possibly close the connection + thread if unauthenticated
        """
        version = ord(self._recv(VERSION_SIZE))
        if version != USERNAME_PASSWORD_VERSION:
            logging.error(f'USERNAME_PASSWORD_VERSION did not match')
            self._send_authentication_failure(FAILURE)

        username_len = self._recv(ID_LEN_SIZE, self._send_authentication_failure, FAILURE)
        username = self._recv(ord(username_len), self._send_authentication_failure, FAILURE)

        password_len = self._recv(PW_LEN_SIZE, self._send_authentication_failure, FAILURE)
        password = self._recv(ord(password_len), self._send_authentication_failure, FAILURE)

        server_username, server_password = self.server._auth  # type: ignore

        if username.decode('utf-8') == server_username and password.decode('utf-8') == server_password:
            self._send(struct.pack("!BB", USERNAME_PASSWORD_VERSION, StatusCode.Success))
            return True

        logging.error(f'Authentication failed')
        self._send_authentication_failure(FAILURE)


"""
@see: https://github.com/itsjfx/python-socks5-server
@see: https://rushter.com/blog/python-socks-server/
@see: https://github.com/rushter/socks5
@see: https://docs.python.org/3/library/socket.html#socket.getaddrinfo
@see: https://docs.python.org/3/library/socket.html#socket-objects
@see: https://docs.python.org/3/library/socketserver.html
@see: https://tools.ietf.org/html/rfc1928
@see: maybe https://github.com/heiher/hev-socks5-tproxy ? 
@see: maybe https://www.edopedia.com/blog/building-a-python-based-secure-web-proxy-server-with-socks5/ ?
"""
if __name__ == '__main__':
    with Ipv6AddressProxyPool() as proxy_pool:
        ProxyRequestHandler.proxy_pool = proxy_pool
        with ThreadingTCPServer(('2a01:4ff:1f0:c596::2', 1081)) as server:
            server.serve_forever()


# import threading

# from socketserver import BaseServer, ThreadingMixIn, TCPServer, StreamRequestHandler

# class Socks5Proxy(threading.Thread):
#     def __init__(self, host='::1', port=1080):
#         super().__init__()
#         self.running = True
#         self.address = (host, port)
#         self.init_socket()

#     def init_socket(self):
#         self.server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
#         self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#         self.server.bind(self.address)
#         self.server.listen(5)

#     def run(self):
#         print(f'Starting SOCKS5 proxy server on {self.address[0]}:{self.address[1]}')
#         try:
#             while self.running:
#                 readable, _, _ = select.select([self.server], [], [], 1)
#                 if readable:
#                     client_socket, client_address = self.server.accept()
#                     print(f'Accepted connection from {client_address}')
#                     client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
#                     client_handler.start()
#         finally:
#             self.server.close()

#     def handle_client(self, client_socket):
#         # Receive the client's request
#         request = client_socket.recv(4096)

#         # Parse the request to extract the destination address and port
#         # For simplicity, let's assume the request is in the form of 'address:port'
#         destination_address, destination_port = request.decode().split(':')

#         # Determine if the address is IPv4 or IPv6
#         address_family = socket.AF_INET if '.' in destination_address else socket.AF_INET6

#         # Create a socket for the remote connection
#         remote_socket = socket.socket(address_family, socket.SOCK_STREAM)

#         # Connect to the destination
#         remote_socket.connect((destination_address, int(destination_port)))

#         # Forward the client's request to the destination
#         remote_socket.sendall(request)

#         # Receive the response from the destination
#         response = remote_socket.recv(4096)

#         # Send the response back to the client
#         client_socket.sendall(response)

#         # Close the remote connection
#         remote_socket.close()


#     def stop(self):
#         self.running = False

# if __name__ == '__main__':
#    proxy = Socks5Proxy()
#    proxy.start()
#    try:
#        while True:
#            pass
#    except KeyboardInterrupt:
#        print('Stopping proxy server...')
#        proxy.stop()
