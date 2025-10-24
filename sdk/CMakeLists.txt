cmake_minimum_required(VERSION 3.10)

project(ElorahtZeroTrustSDK CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(ElorahtZeroTrustSDK STATIC
    Driver.c
    File.c
    Process.c
    Regedit.c
    Communication.cpp
    DriverData.cpp
    FSFilter.cpp
    KernelCommon.cpp
    KernelString.cpp
    ShanonEntropy.cpp
)

target_include_directories(ElorahtZeroTrustSDK PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
