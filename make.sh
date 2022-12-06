#!/bin/sh
make clean;
make
rm test test2 test_vuln
make test
make test2
ln -s standalone/shiva shiva
sudo cp ldso/shiva /lib/shiva
