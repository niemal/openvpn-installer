# openvpn-installer
Automated OpenVPN server setup and client generation with options targeting debian-based server distributions.


## Installation
Just run `./install.sh` with options you wish. For certificate details change the variables `C`, `L`, `O`, and `CN` inside `install.sh` and/or `create_client.sh` respectively.

```
OpenVPN automatic server and client certificate(s) setup script, v0.01 :: Author: niemal
      For a client certificate/package only refer to the create_client.sh script.

Parameters:
  --clients [integer]            - Specifies the amount of client certificates to be automatically created. Default is 1.
  --servername [string(text)]    - Defines the server's name. Default is 'server'.
  --sslconf [absolute(path)]     - Path for the openssl.cnf creation. It is created by default at '/etc/openvpn/openssl.cnf'.
  --certs [absolute(path)]       - Path to the certificates directory. If it doesn't exist, it gets created. Default is '/etc/openvpn/certs'.
  --certmodulus [integer(bit)]   - The RSA modulus bit setting. Default is 2048.
  --expires [integer(days)]      - The certificate expiration in days. Default is 31337.
  --duplicate-cn                 - Allow duplicate certificates in the network. Default is to not.
  --cipher [string(cipher)]      - The server's encryption cipher. Default is AES-256-CBC.
  --port [integer(port)]         - The server's port. Default is 1194.
  --vpnsubnet [string(subnet)]   - The network's subnet, CIDR 24. Default is '10.8.0.0'.
  --dns1 [string(ip)]            - Defines DNS #1 for the server.conf. Default is OpenDNS, 208.67.222.222.
  --dns2 [string(ip)]            - Defines DNS #2 for server.conf. Default is OpenDNS, 208.67.220.220.
  --exitnode                     - Configures iptables so the client can access the internet through the VPN. Requires --iface.
  --iface [string(interface)]    - Declares the interface for --exitnode. Default is eth0.
```

For client certificate generation after installation use the `./create_client.sh` script.
Note: You can create N clients when installing.


## License
GNU lesser general public license, [check here](http://www.gnu.org/licenses/lgpl.html) for the license itself.
