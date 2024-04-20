#!/usr/bin/env python3
import argparse
import ipaddress

from pathlib import Path

from soxprox.pool import Ipv6AddressProxyPool
from soxprox.proxy import ProxyRequestHandler, SOCKS5Proxy


class SoxProxCmd:
    def __init__(self):
        self.__project_dir = self.__get_project_root()

    @staticmethod
    def __get_project_root() -> Path:
        return Path(__file__).parent.parent.parent

    def parse_args(self) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
        bp = argparse.ArgumentParser(add_help=False)
        main_parser = argparse.ArgumentParser(description='Ecommerce Scraper')
        main_parser.add_argument(
            '-v', '--verbose', action='count', default=0, help='Increase verbosity')

        return main_parser, main_parser.parse_args()

    def run(self, main_parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        with Ipv6AddressProxyPool() as proxy_pool:
            ProxyRequestHandler.proxy_pool = proxy_pool
            listen_address = str(ipaddress.IPv6Address(proxy_pool.default_address + 1))
            proxy_pool.create_address(listen_address)
            with SOCKS5Proxy((listen_address, 1081)) as server:
                server.serve_forever()
