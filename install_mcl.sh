#!/usr/bin/env bash
mcl_version="v1.03"
# exit immediately on error
set -e

# check for operating system
os=""
if [ "$(uname)" == "Darwin" ]; then
  os="mac"
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
  os="linux"
else
  echo "Unsupported operating system. This script only works on Linux and macOS."
  exit 2
fi

# check that JAVA_INC is given
if [ $# -eq 0 ]; then
	echo "Missing Java include argument"
	echo "Please specify path of your JDK 'include' directory as first argument"
	if [ $os == "linux" ]; then
    echo "For example: ./install_mcl.sh /usr/lib/jvm/java-8-openjdk-amd64/include"
  else # mac os
    echo "For example: ./install_mcl.sh /Library/Java/JavaVirtualMachines/openjdk-13.0.1.jdk/Contents/Home/include"
    echo "For your system, it's probably: "
    javahome=$(/usr/libexec/java_home)
    echo ./install_mcl.sh $javahome/include
  fi
	exit 1
fi

java_inc=$1

(
  echo "----- Cloning mcl from git://github.com/herumi/mcl -----"
  cd /tmp
  git clone git://github.com/herumi/mcl
  cd mcl
  git checkout $mcl_version || exit
  echo "----- Building mcl -----"
  make -j4 || exit # build mcl library
  echo "----- Building mcl java bindings and running tests -----"
  echo "----- Java include path: $java_inc -----"
  cd ffi/java
  make test_mcl JAVA_INC=-I$java_inc || exit # build java bindings, set include manually
  echo "----- Copying mcl java shared library to /usr/lib/ -----"
  cd ../..
  if [ $os == "linux" ]; then
    sudo cp lib/libmcljava.so /usr/lib/
  else # mac os
    mkdir -p ~/Library/Java/Extensions/ #check that this is included here: System.out.println(System.getProperty("java.library.path"));
	  cp lib/libmcljava.dylib ~/Library/Java/Extensions/
  fi
  echo "----- Installation finished successfully. Deleting mcl repository folder -----"
  cd ..
  rm -rf mcl
  echo "----- Done -----"
) || { echo "----- Failed installation. Deleting mcl folder -----"; rm -rf /tmp/mcl; exit 3; }
