# 1. Build musl-compatible zlib (static + PIC + headers)
cd /tmp
rm -rf zlib-1.3.1
wget -q https://zlib.net/zlib-1.3.1.tar.gz
tar xzf zlib-1.3.1.tar.gz
cd zlib-1.3.1

CC=musl-gcc \
CFLAGS="-fPIC -O3 -D_FORTIFY_SOURCE=2" \
./configure --prefix=/usr/local/musl --static

make -j$(nproc)
sudo make install
sudo ldconfig 2>/dev/null || true

# Verify
ls -la /usr/local/m9usl/lib/libz.a
ls -la /usr/local/musl/include/zlib.h

# 2. Now rebuild libdwarf — it will find musl-built zlib automatically
cd ~/amp/shiva/libdwarf-build/libdwarf-0.10.1
make distclean

CC=musl-gcc \
CFLAGS="-fPIC -O3 -I/usr/local/musl/include" \
LDFLAGS="-L/usr/local/musl/lib" \
./configure \
    --prefix=/usr/local/musl \
    --includedir=/usr/local/musl/include/libdwarf-2 \
    --enable-static \
    --disable-shared \
    --disable-libelf \
    --disable-dwarfexample \
    --disable-dwarfgen

make -j$(nproc)
sudo make install

# Final check
ls -la /usr/local/musl/lib/libdwarf.a
ls -la /usr/local/musl
