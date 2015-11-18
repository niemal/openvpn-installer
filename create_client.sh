#!/usr/bin/env bash
# Author: niem

# Default settings.
outdir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
certs="/etc/openvpn/certs"
sslconf="/etc/openvpn/openssl.cnf"
certmodulus="2048"
clientname="client"
expiration="1337"
C="GG"
L="niemcity"
O="niemorg Ltd"
CN="hermit CA"
cipher="AES-256-CBC"
port="1194"
proto="udp"
serverip=$(cat externalip)

# Colours.
nocolour="\033[0m"
lightgreen="\033[1;32m"
lightcyan="\033[1;36m"
lightgray="\033[0;37m"

# Parsing arguments.
while [ $# -gt 0 ]; do
    case "$1" in
        -od | --outdir)
            shift
            outdir=$1;;
        -c | --certs)
            shift
            certs=$1;;
        -sc | --sslconf)
            shift
            sslconf=$1;;
        -cm | --certmodulus)
            shift
            certmodulus=$1;;
        -cn | --clientname)
            shift
            clientname=$1;;
        -C | --C)
            shift
            C=$1;;
        -L | --L)
            shift
            L=$1;;
        -O | --O)
            shift
            O=$1;;
        -CN | --CN)
            shift
            CN=$1;;
        -e | --expiration)
            shift
            expiration=$1;;
        -ci | --cipher)
            shift
            cipher=$1;;
        -p | --port)
            shift
            port=$1;;
        -proto | --proto)
            shift
            proto=$1;;
        -sip | --serverip)
            shift
            serverip=$1;;
    esac
    shift
done

# Creating the client directory.
mkdir $outdir/$clientname

# Creating the certificate pair, signing it.
echo -e "${lightgreen}[+]--> Creating certificate for $clientname...${lightgray} "
openssl genrsa -des3 -passout pass:qwerty -out $outdir/$clientname/$clientname.key $certmodulus
openssl rsa -passin pass:qwerty -in $outdir/$clientname/$clientname.key -out $outdir/$clientname/$clientname.key
openssl req -config $sslconf -new -subj "/C=$C/L=$L/O=$O/CN=$clientname" -key $outdir/$clientname/$clientname.key -out $outdir/$clientname/$clientname.csr
openssl ca -batch -config $sslconf -days $expiration -in $outdir/$clientname/$clientname.csr -out $outdir/$clientname/$clientname.crt -keyfile $certs/ca.key -cert $certs/ca.crt -policy policy_anything

# Copying ta.key.
cp $certs/ta.key $outdir/$clientname/ta.key

# Creating the .ovpn configuration file.
cat << EOF > $outdir/$clientname/$clientname.ovpn
client
dev tun
proto $proto
ns-cert-type server
remote $serverip $port
cipher $cipher
resolv-retry infinite
nobind
persist-key
persist-tun
ca ca.crt
cert $clientname.crt
key $clientname.key
tls-auth ta.key 1
redirect-gateway def1
verb 1
keepalive 10 900
comp-lzo

EOF


# Copying ca.crt.
cp $certs/ca.crt $outdir/$clientname

# Zipping contents for distribution.
echo -e "${lightgreen}[+] Zipping contents for distribution..${lightcyan} "
zip -j $outdir/$clientname/$clientname.zip $outdir/$clientname/*

echo -e "${lightgreen}[+] The certificates are now located in $outdir/$clientname!${nocolour} "
exit 0

