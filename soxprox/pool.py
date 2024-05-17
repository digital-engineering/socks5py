import ipaddress
import logging
import psutil
import random
import socket
import subprocess

from typing import Literal


class IpAddressProxyPool:
    def __init__(self, logger: logging.Logger, n_ips: int, interface: str = 'eth0'):
        self.__default_address_int = 0
        self.__hostmask_int = 0
        self.__interface = interface
        self.__logger = logger
        self.__n_ips = n_ips
        self.__public_addresses = []

    def __enter__(self) -> 'IpAddressProxyPool':
        try:
            # e.g. '2001:db8::1/64' where /64 is the netmask
            default_ip_masked = sorted(
                self.search_ip_addresses(self.__interface, True),
                key=lambda address: int(ipaddress.IPv6Address(address.split('/')[0]))
            )[0]  # Assume lowest IPv6 address is the default ip
            default_ip = default_ip_masked.split('/')[0]
        except IndexError:
            raise RuntimeError('No IPv6 address found.')

        default_ip_address = ipaddress.IPv6Address(default_ip)
        public_network = ipaddress.IPv6Network(default_ip_masked, strict=False)
        if public_network.network_address > default_ip_address:
            raise RuntimeError(
                'Public network address {} is greater than default ip address. {}'.format(
                    str(public_network.network_address), default_ip
                ))

        self.__default_address_int = int(default_ip_address)
        self.__hostmask_int = int(public_network.hostmask)
        for _ in range(self.__n_ips):
            self.__public_addresses.append(self.__create_random_address())

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.__shutdown()

    @property
    def default_address(self) -> int:
        return self.__default_address_int

    def create_ipv6_address(self, ip_address: str) -> None:
        """Create a new IPv6 address."""
        result = subprocess.run(
            ['sudo', 'ip', '-6', 'addr', 'add', ip_address, 'dev', self.__interface],
            capture_output=True,
            text=True
        )

        if result.returncode == 2:
            raise ValueError(f'IPv6 address already exists: {ip_address}')

        if result.returncode != 0:
            raise RuntimeError(f'Failed to create IPv6 address: {result.stdout}\n{result.stderr}')

    def search_ip_addresses(
            self,
            if_name: str,
            append_mask: bool = False,
            af: int = socket.AF_INET6,
            scope: Literal['global', 'private'] = 'global',
    ) -> list[str]:
        """Find all IP addresses on the interface.

        Given all IP addresses on the interface specified in self.__interface,
        (eth0 by default) return a list of public IP addresses on that interface.

        Args:
            if_name (str, optional):      The interface name, e.g. 'eth0'.
            append_mask (bool, optional): If True, will append the CIDR bitmask. [default: False]
            af (int, optional):           The address family to search for. [default: socket.AF_INET6]
            scope (str, optional):        The scope of the IP address. [default: 'global']

        Returns:
            list[str]: List of public IPv6 addresses on the interface.
        """
        return [
            (f'{address}/{self.__netmask_to_cidr(str(snic.netmask))}'
             if (address := snic.address.replace(f'%{if_name}', ''))
             and append_mask
             else address)
            for snic in (psutil.net_if_addrs().get(if_name) or [])
            if (
                snic.family == af and (
                    scope == 'global' and (
                        ipaddress.IPv4Address(snic.address).is_global if af == socket.AF_INET
                        else ipaddress.IPv6Address(snic.address).is_global)
                    or scope == 'private' and (
                        ipaddress.IPv4Address(snic.address).is_private if af == socket.AF_INET
                        else ipaddress.IPv6Address(snic.address).is_private)
                )
            )
        ]

    def get_random_address(self) -> str:
        """Get a random IP address from the pool."""
        return random.choice(self.__public_addresses)

    def __create_random_address(self) -> str:
        ipv6_address = str(ipaddress.IPv6Address(random.randint(
            self.__default_address_int + 1,
            self.__default_address_int + self.__hostmask_int - 1
        )))
        self.create_ipv6_address(ipv6_address)
        return ipv6_address

    def __netmask_to_cidr(self, netmask: str) -> int:
        """Convert psutil.net_if_addrs().netmask to CIDR notation."""
        HEX_BASE = 16

        # Convert the netmask to binary string
        binary = bin(int(netmask.replace(':', ''), HEX_BASE))

        # Count the number of 1 bits
        return binary.count('1')

    def __shutdown(self) -> None:
        """Remove all ipv6 addresses."""
        for address in self.search_ip_addresses(self.__interface):
            if int(ipaddress.IPv6Address(address)) == self.__default_address_int:
                continue  # DON'T remove the origin public IPv6 address

            result = subprocess.run(
                ['sudo', 'ip', '-6', 'addr', 'del', address, 'dev', self.__interface],
                capture_output=True,
                text=True
            )

            if result.returncode != 0:
                self.__logger.error(
                    f'Failed to remove IPv6 address: {result.stdout}\n{result.stderr}')
