#### Config on server

```bash
ufw allow in on eth0 from 10.0.0.6 to any port 1080
ufw allow in on eth0 from 2a01:4ff:1f0:c6fc::/64 to any port 1080
```