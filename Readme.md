# cryptoTest
Unit testing on cryptographic libraries

# install googletest on Ubuntu
sudo apt-get install libgtest-dev
sudo apt-get install cmake
cd /usr/src/gtest
sudo make CMakeLists.txt
sudo make
sudo cp *.a /usr/lib

# install catch2
wget https://raw.githubusercontent.com/catchorg/Catch2/master/single_include/catch2/catch.hpp
sudo cp catch2.hpp /usr/include
