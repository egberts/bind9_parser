

# cd bind9_parser
# python3 ./setup.py install --user

cd tests/split-horizon-2-bind9-servers
../../examples/parse_bind9.py etc/bind/named-internal.conf

cd ../../examples
./parse_bind9.py named-zytrax.conf
