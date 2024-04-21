#!/usr/bin/env python3
from soxprox.command import SoxProxCmd


"""
@see: https://github.com/itsjfx/python-socks5-server
@see: https://rushter.com/blog/python-socks-server/
@see: https://github.com/rushter/socks5
@see: https://github.com/Amaindex/asyncio-socks-server
@see: https://docs.python.org/3/library/socket.html#socket.getaddrinfo
@see: https://docs.python.org/3/library/socket.html#socket-objects
@see: https://docs.python.org/3/library/socketserver.html
@see: https://tools.ietf.org/html/rfc1928
@see: maybe https://github.com/heiher/hev-socks5-tproxy ? 
@see: maybe https://www.edopedia.com/blog/building-a-python-based-secure-web-proxy-server-with-socks5/ ?
"""
if __name__ == '__main__':
    soxproxcmd = SoxProxCmd()
    main_parser, args = soxproxcmd.parse_args()
    soxproxcmd.run(main_parser, args)
