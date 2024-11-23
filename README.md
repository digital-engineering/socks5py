# socks5py

## Description

SOCKS5 Proxy that works with both IPv4 and IPv6 transparently.

**DISCLAIMER**: This is currenltly only meant to be run on private networks. HTTP authentication is hardcoded to "username" and "password". This is a proof of concept and has not been thoroughly tested in the wild. Use at your own risk!

## Features

Accept SOCKS5 clients on a given address and port, and proxy those requests to any IPv4 or IPv6
address. The client must be IPv6 capable.

## CLI Usage

```bash
./soxprox.py -vv --interface-ipv4=eth0 --scope-ipv4=private
```

## Installation

Only dependencies are Python >= 3.10 standard library. No external libraries required!

#### REQUIRED: Firewall config on server

```bash
ufw allow in on eth0 from 10.0.0.6 to any port 1080
ufw allow in on eth0 from 2a01:4ff:1f0:c6fc::/64 to any port 1080
```

#### 

Add `pipeline` user to `/etc/sudoers.d/pipeline`:

```bash
# /etc/sudoers.d/pipeline
pipeline ALL=(ALL) NOPASSWD: /usr/sbin/ip -6 addr add * dev eth0
pipeline ALL=(ALL) NOPASSWD: /usr/sbin/ip -6 addr del * dev eth0
```

#### Optional: systemd unit file

```bash
sudo cp systemd/soxprox.service /etc/systemd/system/
sudo systemctl enable --now soxprox.service
```

