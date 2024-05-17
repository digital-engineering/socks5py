import ipaddress
import logging
import socket
import time

from threading import Thread
from typing import Any, Literal

from soxprox.pool import IpAddressProxyPool
from soxprox.proxy import ProxyRequestHandler, SOCKS5Proxy


class AppController:
    __LOGGER_FORMAT = '%(asctime)s - %(name)s [%(levelname)s] %(message)s'

    def __init__(self, verbosity: int = 0):
        # Configure logging
        config: dict[str, Any] = {'format': self.__LOGGER_FORMAT}
        if not verbosity:
            config['level'] = logging.WARNING
        elif verbosity == 1:
            config['level'] = logging.INFO
        elif verbosity >= 2:
            config['level'] = logging.DEBUG
        logging.basicConfig(**config)

        # Create logger
        self.__logger = logging.getLogger('soxprox')

    def run(
        self,
        n_ips: int,
        port: int,
        if_ipv4: str,
        scope_ipv4: Literal['global', 'private'] = 'private'
    ) -> None:
        pool = IpAddressProxyPool(self.__logger, n_ips)

        # Create threads
        thread1 = Thread(target=self._serve_ipv4, args=(pool, port, if_ipv4, scope_ipv4))
        thread2 = Thread(target=self._start_ipv6_server, args=(pool, port))

        # Start threads
        thread1.start()
        thread2.start()

        # Wait for both threads to complete
        thread1.join()
        thread2.join()

    def _serve_ipv4(
        self,
        proxy_pool: IpAddressProxyPool,
        listen_port: int,
        interface: str,
        scope: Literal['global', 'private']
    ) -> None:
        # Find the private IP addresses
        ipv4_addresses = proxy_pool.search_ip_addresses(interface, False, socket.AF_INET, scope)
        # Start the server
        with SOCKS5Proxy((ipv4_addresses[0], listen_port)) as server:
            self.__logger.info(f'Listening on {ipv4_addresses[0]}:{listen_port}')
            server.serve_forever()

    def _start_ipv6_server(self, proxy_pool: IpAddressProxyPool, listen_port: int) -> None:
        with proxy_pool:
            ProxyRequestHandler.proxy_pool = proxy_pool
            ProxyRequestHandler.logger = self.__logger
            ipv6_listen_address = str(ipaddress.IPv6Address(proxy_pool.default_address + 1))
            try:
                proxy_pool.create_ipv6_address(ipv6_listen_address)
                time.sleep(3)  # give the system some time to register the address
            except ValueError:
                self.__logger.info(f'Address {ipv6_listen_address} already exists.')

            try:
                with SOCKS5Proxy((ipv6_listen_address, listen_port)) as server:
                    self.__logger.info(f'Listening on [{ipv6_listen_address}]:{listen_port}')
                    server.serve_forever()

            except OSError as e:
                self.__logger.error(f'{e} for address {ipv6_listen_address}')
