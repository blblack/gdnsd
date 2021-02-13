#!/bin/sh
# run from top of repo
if [ ! -f $PWD/qa/gdnsd.supp ]; then
   echo "Run this from the root of the source tree!"
   exit 99
fi

# Note this uses gcc-8's sanitizers, this probably won't work with earlier gcc versions or other variants

set -x
set -e
CPPFLAGS="-DGDNSD_USE_GRCU_C11A" CFLAGS="-O2 -g -fno-omit-frame-pointer -fno-common -fno-sanitize-recover=all -fsanitize=thread" CC=gcc-10 ./configure --enable-developer --without-hardening
make clean
SLOW_TESTS=1 make check
