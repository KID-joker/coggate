cmake_minimum_required(VERSION 3.16)
project(coggate_phase5b LANGUAGES C CXX)

include(CTest)
find_package(nlohmann_json 3.11 REQUIRED)

set(COGGATE_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../packages/ffi/include"
    CACHE PATH "Directory containing coggate.h")
set(COGGATE_LIBRARY "" CACHE FILEPATH "Exact CogGate native link library")
set(COGGATE_RUNTIME_LIBRARY "" CACHE FILEPATH
    "CogGate runtime DLL when COGGATE_LIBRARY is a Windows import library")
option(COGGATE_STATIC "Link the CogGate static library" OFF)

if(NOT EXISTS "${COGGATE_INCLUDE_DIR}/coggate.h")
  message(FATAL_ERROR "COGGATE_INCLUDE_DIR does not contain coggate.h")
endif()
if(NOT COGGATE_LIBRARY OR NOT EXISTS "${COGGATE_LIBRARY}")
  message(FATAL_ERROR "COGGATE_LIBRARY must name an existing native library")
endif()

if(COGGATE_STATIC)
  add_library(coggate_ffi STATIC IMPORTED GLOBAL)
  target_compile_definitions(coggate_ffi INTERFACE COGGATE_STATIC)
else()
  add_library(coggate_ffi SHARED IMPORTED GLOBAL)
endif()

if(WIN32 AND NOT MSVC)
  message(FATAL_ERROR "Phase 5B Windows native targets require MSVC")
endif()

set_target_properties(coggate_ffi PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${COGGATE_INCLUDE_DIR}")
if(WIN32 AND NOT COGGATE_STATIC)
  if(NOT COGGATE_RUNTIME_LIBRARY OR NOT EXISTS "${COGGATE_RUNTIME_LIBRARY}")
    message(FATAL_ERROR
      "COGGATE_RUNTIME_LIBRARY must name the CogGate runtime DLL")
  endif()
  set_target_properties(coggate_ffi PROPERTIES IMPORTED_IMPLIB "${COGGATE_LIBRARY}")
  set_target_properties(coggate_ffi PROPERTIES
    IMPORTED_LOCATION "${COGGATE_RUNTIME_LIBRARY}")
else()
  set_target_properties(coggate_ffi PROPERTIES IMPORTED_LOCATION "${COGGATE_LIBRARY}")
endif()

add_subdirectory(c)
add_subdirectory(cpp)
