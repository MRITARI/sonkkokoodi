cmake_minimum_required(VERSION 3.16)
project(Sonkkokoodi VERSION 1.0.0 LANGUAGES CXX)

# Require C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Enable Qt auto-generators
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 modules (Core, Gui, Widgets, and Network are required)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network)

# Find OpenSSL for AES-GCM and ECDSA cryptography
find_package(OpenSSL REQUIRED)

# ==============================================================================
# 1. THE MAIN SECURE CHAT APPLICATION
# ==============================================================================
add_executable(sonkkokoodi main.cpp)

# Link Qt and OpenSSL to the main app
target_link_libraries(sonkkokoodi PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    OpenSSL::Crypto
)

# Hide the black console window on Windows (Ignored on Linux)
set_target_properties(sonkkokoodi PROPERTIES WIN32_EXECUTABLE TRUE)

# ==============================================================================
# 2. THE DEPLOYMENT INSTALLER
# ==============================================================================
add_executable(sonkkokoodi_installer installer.cpp)

# The installer doesn't need OpenSSL, just Qt UI and Networking
target_link_libraries(sonkkokoodi_installer PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
)

# Hide the black console window on Windows (Ignored on Linux)
set_target_properties(sonkkokoodi_installer PROPERTIES WIN32_EXECUTABLE TRUE)
