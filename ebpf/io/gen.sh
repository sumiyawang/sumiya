#!/bin/bash
sed -i 's/#define K514 .*/#define K514 0/' src/headers/ver.h
make
mv ../bin/io ../bin/iov0
sed -i 's/#define K514 .*/#define K514 1/' src/headers/ver.h
make
mv ../bin/io ../bin/iov1
