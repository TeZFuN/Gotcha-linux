cmake_minimum_required(VERSION 3.16)
project(GotchaLinux LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# ---- Qt6 (fallback на Qt5) ----
find_package(Qt6 QUIET COMPONENTS Widgets Network)
if(Qt6_FOUND)
    set(QT_LIBS Qt6::Widgets Qt6::Network)
    message(STATUS "Using Qt6")
else()
    find_package(Qt5 REQUIRED COMPONENTS Widgets Network)
    set(QT_LIBS Qt5::Widgets Qt5::Network)
    message(STATUS "Using Qt5")
endif()

# ---- libpcap ----
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# ---- Исполняемый файл ----
add_executable(GotchaLinux main.cpp)

target_include_directories(GotchaLinux PRIVATE ${PCAP_INCLUDE_DIRS})

target_link_libraries(GotchaLinux PRIVATE
    ${QT_LIBS}
    ${PCAP_LIBRARIES}
)

target_compile_options(GotchaLinux PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# Установка (опционально): sudo cmake --install build
install(TARGETS GotchaLinux RUNTIME DESTINATION bin)