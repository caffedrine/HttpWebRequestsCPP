cmake_minimum_required(VERSION 3.6)
project(HttpWebRequests_Winsock)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -static-libgcc -static-libstdc++")

set(SOURCE_FILES main.cpp HttpWebRequests.cpp)
add_executable(HttpWebRequests_Winsock ${SOURCE_FILES})

target_link_libraries(HttpWebRequests_Winsock gdi32.lib ws2_32.lib)
