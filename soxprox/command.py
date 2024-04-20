#!/usr/bin/env python3
import argparse

from soxprox.controller import AppController


class SoxProxCmd:

    def parse_args(self) -> tuple[argparse.ArgumentParser, argparse.Namespace]:
        main_parser = argparse.ArgumentParser(description='Ecommerce Scraper')
        main_parser.add_argument(
            '-v', '--verbose', action='count', default=0, help='Increase verbosity')

        return main_parser, main_parser.parse_args()

    def run(self, main_parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
        app_controller = AppController()
        app_controller.run()
