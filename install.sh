#!/usr/bin/env bash
# Author: niemal
# Distro-target: Debian

# Certificate default details.
C="GG"
L="niemcity"
O="niemorg Ltd"
CN="hermit CA"

# Default settings.
clients="1"
servername="server"
sslconf="/etc/openvpn/openssl.cnf"
certs="/etc/openvpn/certs"
certmodulus="2048"
expiration="31337"
duplicatecn=""
cipher="AES-256-CBC"
port="1194"
proto="udp"
vpnsubnet="10.8.0.0"
dns1="208.67.222.222"
dns2="208.67.220.220"
exitnode=false
iface="eth0"

# Colours.
lightred="\033[1;31m"
nocolour="\033[0m"
lightgreen="\033[1;32m"
white="\033[1;37m"
yellow="\033[1;33m"

# Parsing arguments.
while [ $# -gt 0 ]; do
    case "$1" in
        -h | --help)
            echo -e "${yellow}OpenVPN automatic server and client certificate(s) setup script, v0.01 :: Author: niemal"
            echo -e "      ${white}For a client certificate/package only refer to the create_client.sh script.\n"
            echo -e "Parameters:"
            echo -e "  $lightred--clients $white[integer]$nocolour            - Specifies the amount of client certificates to be automatically created. Default is 1."
            echo -e "  $lightred--servername $white[string(text)]$nocolour    - Defines the server's name. Default is 'server'."
            echo -e "  $lightred--sslconf $white[absolute(path)]$nocolour     - Path for the openssl.cnf creation. It is created by default at '/etc/openvpn/openssl.cnf'."
            echo -e "  $lightred--certs $white[absolute(path)]$nocolour       - Path to the certificates directory. If it doesn't exist, it gets created. Default is '/etc/openvpn/certs'."
            echo -e "  $lightred--certmodulus $white[integer(bit)]$nocolour   - The RSA modulus bit setting. Default is 2048."
            echo -e "  $lightred--expires $white[integer(days)]$nocolour      - The certificate expiration in days. Default is 31337."
            echo -e "  $lightred--duplicate-cn$nocolour                 - Allow duplicate certificates in the network. Default is to not."
            echo -e "  $lightred--cipher $white[string(cipher)]$nocolour      - The server's encryption cipher. Default is AES-256-CBC."
            echo -e "  $lightred--port $white[integer(port)]$nocolour         - The server's port. Default is 1194."
            echo -e "  $lightred--vpnsubnet $white[string(subnet)]$nocolour   - The network's subnet, CIDR 24. Default is '10.8.0.0'."
            echo -e "  $lightred--dns1 $white[string(ip)]$nocolour            - Defines DNS #1 for the server.conf. Default is OpenDNS, 208.67.222.222."
            echo -e "  $lightred--dns2 $white[string(ip)]$nocolour            - Defines DNS #2 for server.conf. Default is OpenDNS, 208.67.220.220."
            echo -e "  $lightred--exitnode$nocolour                     - Configures iptables so the client can access the internet through the VPN. Requires --iface."
            echo -e "  $lightred--iface $white[string(interface)]$nocolour    - Declares the interface for --exitnode. Default is eth0."
            exit 0;;
        -c | --clients)
            shift
            clients=$1;;
        -s | --servername)
            shift
            servername=$1;;
        -ssl | --sslconf)
            shift
            sslconf=$1;;
        -ce | --certs)
            shift
            certs=$1;;
        -cm | --certmodulus)
            shift
            certmodulus=$1;;
        -e | --expires)
            shift
            expiration=$1;;
        -dcn | --duplicate-cn)
            shift
            duplicatecn="duplicate-cn";;
        -ci | --cipher)
            shift
            cipher=$1;;
        -p | --port)
            shift
            port=$1;;
        -pro | --proto)
            shift
            proto=$1;;
        -sub | --vpnsubnet)
            shift
            vpnsubnet=$1;;
        -d1 | --dns1)
            shift
            dns1=$1;;
        -d2 | --dns2)
            shift
            dns2=$1;;
        -en | --exitnode)
            shift
            exitnode=true;;
        -if | --iface)
            shift
            iface=$1;;
    esac
    shift
done

# Checking for --extinode and --iface.
if [ "$exitnode" = true ]; then
    # Forwarding IPv4.
    echo 1 > /proc/sys/net/ipv4/ip_forward
    # Adding iptables rule.
    iptables -t nat -A POSTROUTING -s $vpnsubnet/24 -o $iface -j MASQUERADE
fi


# Installing openvpn plus a few extras and creating the certs directory.
apt-get install openssl openvpn udev zip curl

if [ ! -d /etc/openvpn ]; then
    echo -e "${lightred}Something went wrong with the installation, /etc/openvpn doesn't exist.${nocolour} "
    exit 0
elif [ ! -d /etc/openvpn/certs ]; then
    mkdir $certs && mkdir $certs/clients
    echo -e "${lightgreen}[+] $certsdir directory was created successfully.${nocolour} "
fi

# Checing if serial file exists, if not we create it.
if [ ! -f $certs/serial ]; then
    echo 00 > $certs/serial
fi

# Checking if crlnumber exists, if not we create it.
if [ ! -f $certs/crlnumber ]; then
    echo 00 > $certs/crlnumber
fi

# Checking if index.txt exists inside $certs directory. If not, we create it.
if [ ! -f $certs/index.txt ]; then
    touch $certs/index.txt
fi

# Checking if there is an openssl.cnf already, or else we create it.
if [ ! -f $sslconf ]; then
    cat << EOF > $sslconf
HOME                    = .
RANDFILE                = \$ENV::HOME/.rnd
oid_section             = new_oids

[ new_oids ]
tsa_policy1 = 1.2.3.4.1
tsa_policy2 = 1.2.3.4.5.6
tsa_policy3 = 1.2.3.4.5.7

[ ca ]
default_ca      = CA_default            # The default ca section

[ CA_default ]
dir             = $certs            # Where everything is kept
certs           = \$dir               # Where the issued certs are kept
crl_dir         = \$dir              # Where the issued crl are kept
database        = \$dir/index.txt        # database index file.
new_certs_dir   = \$dir
certificate     = \$dir/ca.crt           # The CA certificate
serial          = \$dir/serial           # The current serial number
crlnumber       = \$dir/crlnumber        # the current crl number
crl             = \$dir/crl.pem          # The current CRL
private_key     = \$dir/ca.key            # The private key
RANDFILE        = \$dir/private/.rand    # private random number file
x509_extensions = usr_cert              # The extentions to add to the cert
name_opt        = ca_default            # Subject Name options
cert_opt        = ca_default            # Certificate field options
default_days    = 365                   # how long to certify for
default_crl_days= 30                    # how long before next CRL
default_md      = default               # use public key default MD
preserve        = no                    # keep passed DN ordering
policy          = policy_match

[ policy_match ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_anything ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

####################################################################
[ req ]
default_bits            = 2048
default_keyfile         = privkey.pem
distinguished_name      = req_distinguished_name
attributes              = req_attributes
x509_extensions = v3_ca
string_mask = utf8only


[ req_distinguished_name ]
countryName                     = Country Name (2 letter code)
countryName_default             = AU
countryName_min                 = 2
countryName_max                 = 2
stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Some-State
localityName                    = Locality Name (eg, city)
0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = Internet Widgits Pty Ltd
organizationalUnitName          = Organizational Unit Name (eg, section)
commonName                      = Common Name (e.g. server FQDN or YOUR name)
commonName_max                  = 64
emailAddress                    = ayy@lmao.com
emailAddress_max                = 64


[ req_attributes ]
challengePassword               = A challenge password
challengePassword_min           = 4
challengePassword_max           = 20
unstructuredName                = An optional company name

[ usr_cert ]
basicConstraints=CA:FALSE
nsComment                       = "Powered by niemal"
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment

[ v3_ca ]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer
basicConstraints = CA:true


[ crl_ext ]
authorityKeyIdentifier=keyid:always

[ proxy_cert_ext ]
basicConstraints=CA:FALSE
nsComment                       = "Powered by niemal"
# PKIX recommendations harmless if included in all certificates.
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
proxyCertInfo=critical,language:id-ppl-anyLanguage,pathlen:3,policy:foo

####################################################################
[ tsa ]
default_tsa = tsa_config1       # the default TSA section

[ tsa_config1 ]
# These are used by the TSA reply generation only.
dir             = $certs              # TSA root directory
serial          = \$dir/tsaserial        # The current serial number (mandatory)
crypto_device   = builtin               # OpenSSL engine to use for signing
signer_cert     = \$dir/tsacert.pe
certs           = \$dir/cacert.pem
signer_key      = \$dir/private/tsakey.pem # The TSA private key (optional)
default_policy  = tsa_policy1
other_policies  = tsa_policy2, tsa_policy3      # acceptable policies (optional)
digests         = md5, sha1             # Acceptable message digests (mandatory)
accuracy        = secs:1, millisecs:500, microsecs:100  # (optional)
clock_precision_digits  = 0     # number of digits after dot. (optional)
ordering                = yes   # Is ordering defined for timestamps?
tsa_name                = yes   # Must the TSA name be included in the reply?
ess_cert_id_chain       = no    # Must the ESS cert id chain be included?

EOF
fi


# Creating CA certificate with openssl.
echo -e "${lightgreen}[*] Creating the CA pair...${white} "
openssl genrsa -des3 -passout pass:qwerty -out $certs/ca.key $certmodulus
openssl rsa -passin pass:qwerty -in $certs/ca.key -out $certs/ca.key
openssl req -config $sslconf -new -x509 -subj "/C=$C/L=$L/O=$O CA/CN=$CN" -days $expiration -key $certs/ca.key -out $certs/ca.crt


# Creating server certificate.
echo -e "${lightgreen}[*] Creating the server pair, signing it with our CA...${white} "
openssl genrsa -des3 -passout pass:qwerty -out $certs/$servername.key $certmodulus
openssl rsa -passin pass:qwerty -in $certs/$servername.key -out $certs/$servername.key
# Creating a Certificate Sign Request so our CA can sign it.
openssl req -config $sslconf -new -subj "/C=$C/L=$L/O=$O/CN=$CN" -key $certs/$servername.key -out $certs/$servername.csr
# Finally we sign the certificate with our CA.
openssl ca -batch -config $sslconf -days $expiration -in $certs/$servername.csr -outdir $certs -out $certs/$servername.crt -keyfile $certs/ca.key -cert $certs/ca.crt -policy policy_anything


# Building Diffie Hellman key exchange parameters.
openssl dhparam -dsaparam -out $certs/dh$certmodulus.pem $certmodulus

# Creating TA key for DDoS protection.
openvpn --genkey --secret $certs/ta.key

# Grabbing our IP for client configuration.
curl -s http://myexternalip.com/raw > externalip

# Making create_client.sh executable.
chmod +x create_client.sh
# Creating client certificates.
for ((i=1; i<=clients; i++));
do
    ./create_client.sh --outdir $certs/clients --certs $certs --certmodulus $certmodulus --clientname client$i --C $C --L $L --O $O --CN $CN --expiration $expiration
done

# Creating our server.conf.
cat << EOF > /etc/openvpn/server.conf
port $port
proto $proto
dev tun
#plugin /usr/lib/openvpn/openvpn-plugin-auth-pam.so login
ca $certs/ca.crt
cert $certs/server.crt
key $certs/server.key
dh $certs/dh$certmodulus.pem
server $vpnsubnet 255.255.255.0
push "redirect-gateway def1 bypass-dhcp"
push "remote-gateway $(cat externalip)"
push "dhcp-option DNS $dns1"
push "dhcp-option DNS $dns2"
keepalive 10 120
tls-auth $certs/ta.key 0
cipher $cipher
comp-lzo
user nobody
group nogroup
persist-key
persist-tun
verb 3
script-security 3
$duplicatecn

EOF

service openvpn restart
echo -e "${yellow}[+] Ahoy, the course is set.${nocolour} "
exit 0
