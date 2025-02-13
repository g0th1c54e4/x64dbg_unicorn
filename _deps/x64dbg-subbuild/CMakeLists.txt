# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.28.0-rc3)

# Reject any attempt to use a toolchain file. We must not use one because
# we could be downloading it here. If the CMAKE_TOOLCHAIN_FILE environment
# variable is set, the cache variable will have been initialized from it.
unset(CMAKE_TOOLCHAIN_FILE CACHE)
unset(ENV{CMAKE_TOOLCHAIN_FILE})

# We name the project and the target for the ExternalProject_Add() call
# to something that will highlight to the user what we are working on if
# something goes wrong and an error message is produced.

project(x64dbg-populate NONE)



include(ExternalProject)
ExternalProject_Add(x64dbg-populate
                     "UPDATE_DISCONNECTED" "False" "DOWNLOAD_EXTRACT_TIMESTAMP" "FALSE" "EXTERNALPROJECT_INTERNAL_ARGUMENT_SEPARATOR" "URL" "https://sourceforge.net/projects/x64dbg/files/snapshots/snapshot_2023-06-10_18-05.zip" "URL_HASH" "SHA1=04468bd61fb36d6b10d17f342f03ef12f5b2ce62"
                    SOURCE_DIR          "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-src"
                    BINARY_DIR          "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-build"
                    CONFIGURE_COMMAND   ""
                    BUILD_COMMAND       ""
                    INSTALL_COMMAND     ""
                    TEST_COMMAND        ""
                    USES_TERMINAL_DOWNLOAD  YES
                    USES_TERMINAL_UPDATE    YES
                    USES_TERMINAL_PATCH     YES
)


