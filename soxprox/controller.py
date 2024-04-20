import ipaddress
import logging
import time

from soxprox.pool import Ipv6AddressProxyPool
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

    def run(self,  n_ips: int, listen_port: int = 1081) -> None:
        with Ipv6AddressProxyPool(self.__logger, n_ips) as proxy_pool:
            ProxyRequestHandler.proxy_pool = proxy_pool
            ProxyRequestHandler.logger = self.__logger
            listen_address = str(ipaddress.IPv6Address(proxy_pool.default_address + 1))
            try:
                proxy_pool.create_address(listen_address)
                time.sleep(3)  # give the system some time to register the address
            except ValueError:
                self.__logger.info(f'Address {listen_address} already exists.')

            try:
                with SOCKS5Proxy((listen_address, listen_port)) as server:
                    self.__logger.info(f'Listening on [{listen_address}]:{listen_port}')
                    server.serve_forever()

            except OSError as e:
                self.__logger.error(f'{e} for address {listen_address}')
