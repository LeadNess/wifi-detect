cmake_minimum_required(VERSION 3.15)
project(WifiSniffer)

set(CMAKE_CXX_STANDARD 20)

add_executable(WifiSniffer main.cpp sniffer.cpp sniffer.h)