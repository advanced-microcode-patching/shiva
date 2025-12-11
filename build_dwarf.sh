wget -qO- https://www.prevanders.net/libdwarf-0.10.1.tar.xz | tar xJ && \
cd libdwarf-0.10.1 && \
CC=musl-gcc CFLAGS="-Os -static" ./configure --prefix=/usr/local/musl --enable-static --disable-shared --with-libdwarf-include-style=libdwarf-2 --disable-debuginfod && \
make -j$(nproc) && sudo make install && \
echo "libdwarf.a is now at /usr/local/musl/lib/libdwarf.a"
