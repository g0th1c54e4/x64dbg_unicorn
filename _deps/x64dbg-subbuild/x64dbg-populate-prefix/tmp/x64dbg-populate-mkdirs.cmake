# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION 3.5)

file(MAKE_DIRECTORY
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-src"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-build"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/tmp"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/src/x64dbg-populate-stamp"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/src"
  "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/src/x64dbg-populate-stamp"
)

set(configSubDirs Debug)
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/src/x64dbg-populate-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "E:/Chrome Download/PluginTemplate-main/build/_deps/x64dbg-subbuild/x64dbg-populate-prefix/src/x64dbg-populate-stamp${cfgdir}") # cfgdir has leading slash
endif()
