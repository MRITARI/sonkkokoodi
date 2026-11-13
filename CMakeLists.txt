cmake_minimum_required(VERSION 3.16)
project(Sonkkokoodi VERSION 1.0.0 LANGUAGES CXX)

# Require C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# The sources contain UTF-8 literals (Sönkkökoodi, ✓, ≡); MSVC needs to be told
if(MSVC)
    add_compile_options(/utf-8)
endif()

# Enable Qt auto-generators
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Find Qt6 modules (Core, Gui, Widgets, and Network are required)
find_package(Qt6 REQUIRED COMPONENTS Core Gui Widgets Network Test)

# Find OpenSSL for AES-GCM and ECDSA cryptography
find_package(OpenSSL REQUIRED)

# ==============================================================================
# 1. THE MAIN SECURE CHAT APPLICATION
# ==============================================================================
# Crypto primitives live in a GUI-free library so they can be unit tested.
add_library(sk_crypto STATIC sk_crypto.cpp)
target_include_directories(sk_crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(sk_crypto PUBLIC Qt6::Core OpenSSL::Crypto)

add_executable(sonkkokoodi main.cpp)

# Link Qt and OpenSSL to the main app
target_link_libraries(sonkkokoodi PRIVATE
    Qt6::Core
    Qt6::Gui
    Qt6::Widgets
    Qt6::Network
    OpenSSL::Crypto
    sk_crypto
)

# Hide the black console window on Windows (Ignored on Linux)
set_target_properties(sonkkokoodi PROPERTIES WIN32_EXECUTABLE TRUE)

# ==============================================================================
# 2. THE DEPLOYMENT INSTALLER
# ==============================================================================
# The installer relies on PowerShell and .lnk shortcuts, so it is Windows-only.
if(WIN32)
    add_executable(sonkkokoodi_installer installer.cpp)

    # The installer doesn't need OpenSSL, just Qt UI and Networking
    target_link_libraries(sonkkokoodi_installer PRIVATE
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
    )

    # Hide the black console window
    set_target_properties(sonkkokoodi_installer PROPERTIES WIN32_EXECUTABLE TRUE)
endif()

# ==============================================================================
# 3. TESTS  (ctest --test-dir build --output-on-failure)
# ==============================================================================
enable_testing()
add_executable(test_crypto tests/test_crypto.cpp)
target_link_libraries(test_crypto PRIVATE sk_crypto Qt6::Test)
add_test(NAME crypto COMMAND test_crypto)
