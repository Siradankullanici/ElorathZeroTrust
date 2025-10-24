cmake_minimum_required(VERSION 3.10)

project(ElorahtZeroTrustSDK C)

set(CMAKE_C_STANDARD 11)

add_library(ElorahtZeroTrustSDK STATIC
    Driver.c
    File.c
    Process.c
    Regedit.c
)

target_include_directories(ElorahtZeroTrustSDK PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
