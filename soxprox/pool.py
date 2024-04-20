import ipaddress
import logging
import psutil
import random
import socket
import subprocess


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
                self.__find_allocated_ip_addresses(True),
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
        self.__addresses = []
        for _ in range(self.__n_ips):
            self.__addresses.append(self.__create_random_address())

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.__shutdown()

    @property
    def default_address(self) -> int:
        return self.__default_address_int

    def create_address(self, ip_address: str) -> None:
        """Create a new IP address."""
        result = subprocess.run(
            ['sudo', 'ip', '-6', 'addr', 'add', ip_address, 'dev', self.INTERFACE],
            capture_output=True,
            text=True
        )

        if result.returncode == 2:
            self.__logger.info(f'IP address already exists: {ip_address}')
            return

        if result.returncode != 0:
            raise RuntimeError(f'Failed to create IP address: {result.stdout}\n{result.stderr}')

    def get_random_address(self) -> str:
        """Get a random IP address from the pool."""
        return random.choice(self.__addresses)

    def __create_random_address(self) -> str:
        ipv6_address = str(ipaddress.IPv6Address(random.randint(
            self.__default_address_int + 1,
            self.__default_address_int + self.__hostmask_int - 1
        )))
        self.create_address(ipv6_address)
        return ipv6_address

    def __find_allocated_ip_addresses(self, append_mask: bool = False) -> list[str]:
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

    def __netmask_to_cidr(self, netmask: str) -> int:
        """Convert psutil.net_if_addrs().netmask to CIDR notation."""
        HEX_BASE = 16

        # Convert the netmask to binary string
        binary = bin(int(netmask.replace(':', ''), HEX_BASE))

        # Count the number of 1 bits
        return binary.count('1')

    def __shutdown(self) -> None:
        """Remove all ipv6 addresses."""
        for address in self.__find_allocated_ip_addresses():
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
