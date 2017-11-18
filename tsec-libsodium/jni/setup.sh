#!/usr/bin/env bash
#Setup script adapted from android libsodium library
set -e

if [ -z "$JAVA_HOME" ]; then
    echo "ERROR You should set JAVA_HOME"
    echo "Exiting!"
    exit 1
fi

echo "${JAVA_HOME}"


C_INCLUDE_PATH="${JAVA_HOME}/include:${JAVA_HOME}/include/linux:/System/Library/Frameworks/JavaVM.framework/Headers"
export C_INCLUDE_PATH

rm -f *.java
rm -f *.c
rm -f *.so

export PATH=/usr/local/bin:$PATH

swig -java -package tsec.jni sodium.i


jnilib=libsodiumjni.so
destlib=/usr/lib
sudo ldconfig
echo $jnilib
echo $destlib
echo $destlib/$jnilib


gcc -I../usr/local/include/sodium -I${JAVA_HOME}/include -I${JAVA_HOME}/include/linux sodium_wrap.c -shared -fPIC -L/usr/local/lib -L/usr/lib -lsodium -o $jnilib
sudo rm -f $destlib/$jnilib
sudo cp $jnilib $destlib
