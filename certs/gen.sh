#!/bin/sh
set -eu
cd "$(dirname "$0")"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout ca.key -out ca.crt -days 3650 -subj "/CN=rust-toy-0rtt test ca" 2>/dev/null

openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout leaf.key -out leaf.csr -subj "/CN=localhost" 2>/dev/null

cat > leaf.ext <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -in leaf.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out leaf.crt -days 3650 -extfile leaf.ext 2>/dev/null

rm -f leaf.csr leaf.ext ca.srl
echo "wrote ca.crt leaf.crt leaf.key in $(pwd)"
