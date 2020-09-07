#!/bin/bash
# File: generate-key.sh
# Title: Generate keys for use with IXFR/AXFR secured (TSIG) session

echo -n "Enter in hostname (ending with a period): "
read -r MYHOST
if [ -z "$MYHOST" ]; then
    exit 1
fi

KEYGEN=$(which dnssec-keygen)
if [ ! -x "$KEYGEN" ]; then
  echo "Keygen binary is missing;  missing package?"
  exit 2
fi
dnssec-keygen -a HMAC-SHA512 -b 512 -n USER $1
