import ipaddress

from soxprox.pool import Ipv6AddressProxyPool
from soxprox.proxy import ProxyRequestHandler, SOCKS5Proxy


class AppController:
    def run(self) -> None:
        with Ipv6AddressProxyPool() as proxy_pool:
            ProxyRequestHandler.proxy_pool = proxy_pool
            listen_address = str(ipaddress.IPv6Address(proxy_pool.default_address + 1))
            proxy_pool.create_address(listen_address)
            try:
                with SOCKS5Proxy((listen_address, 1081)) as server:
                    server.serve_forever()

            except OSError as e:
                print(f'Error: {e} for address {listen_address}')
