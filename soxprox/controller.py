import ipaddress
import logging
import socket
import threading
import time

from soxprox.pool import IpAddressProxyPool
from soxprox.proxy import ProxyRequestHandler, SOCKS5Proxy


class AppController:
    def __init__(self, verbosity: int = 0):
        if not verbosity:
            verbosity = logging.WARNING
        elif verbosity == 1:
            verbosity = logging.INFO
        elif verbosity >= 2:
            verbosity = logging.DEBUG
        logging.basicConfig(level=verbosity)
        self.__logger = logging.getLogger('soxprox')

    def run(self,  n_ips: int, listen_port: int = 1080) -> None:
        proxy_pool = IpAddressProxyPool(self.__logger, n_ips)
        # Create threads
        thread1 = threading.Thread(target=self._start_ipv4_server, args=(proxy_pool, listen_port))
        thread2 = threading.Thread(target=self._start_ipv6_server, args=(proxy_pool, listen_port))

        # Start threads
        thread1.start()
        thread2.start()

        # Wait for both threads to complete
        thread1.join()
        thread2.join()        

    def _start_ipv4_server(self, proxy_pool: IpAddressProxyPool, listen_port: int):
        ipv4_addresses = proxy_pool.find_allocated_ip_addresses(af=socket.AF_INET, scope='private')
        with SOCKS5Proxy((ipv4_addresses[0], listen_port)) as server:
            self.__logger.info(f'Listening on {ipv4_addresses[0]}:{listen_port}')
            server.serve_forever()

    def _start_ipv6_server(self, proxy_pool: IpAddressProxyPool, listen_port: int):
        with proxy_pool:
            ProxyRequestHandler.proxy_pool = proxy_pool
            ProxyRequestHandler.logger = self.__logger
            ipv6_listen_address = str(ipaddress.IPv6Address(proxy_pool.default_address + 1))
            try:
                proxy_pool.create_address(ipv6_listen_address)
                time.sleep(3)  # give the system some time to register the address
            except ValueError:
                self.__logger.info(f'Address {ipv6_listen_address} already exists.')

            try:
                with SOCKS5Proxy((ipv6_listen_address, listen_port)) as server:
                    self.__logger.info(f'Listening on [{ipv6_listen_address}]:{listen_port}')
                    server.serve_forever()

            except OSError as e:
                self.__logger.error(f'{e} for address {ipv6_listen_address}')
