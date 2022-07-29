#!/bin/sh
make clean;
make
rm test test2 test_vuln
make test
make test2
make test_vuln
ln -s standalone/shiva shiva
