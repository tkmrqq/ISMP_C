cmake_minimum_required(VERSION 3.27)
project(ICMP)

set(CMAKE_CXX_STANDARD 17)

add_executable(ICMP main.cpp)
target_link_libraries(ICMP ws2_32 iphlpapi)
