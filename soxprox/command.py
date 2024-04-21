#!/usr/bin/env python3
import argparse

from soxprox.controller import AppController


class SoxProxCmd:

    def parse_args(self) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
        main_parser = argparse.ArgumentParser(description='Ecommerce Scraper')
        main_parser.add_argument(
            '--n-ips', type=int, default=3,
            help='Number of IP addresses for ipv6 proxy [default: 3]')
        main_parser.add_argument(
            '--interface-ipv4', type=str, default='eth0',
            help='Iterface for ipv4 proxy listen address [default: eth0]')
        main_parser.add_argument(
            '--port', type=int, default=1080,
            help='Listen port for proxy listen [default: 1080]')
        main_parser.add_argument(
            '--scope-ipv4', type=str, default='global',
            help='Scope for ipv4 proxy listen address [ "global" | "private" ] [default: global]')
        main_parser.add_argument(
            '-v', '--verbose', action='count', default=0, help='Increase verbosity')

        return main_parser, main_parser.parse_args()

    def run(self, main_parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        app_controller = AppController(args.verbose)
        app_controller.run(args.n_ips, args.port, args.interface_ipv4, args.scope_ipv4)
