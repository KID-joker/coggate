cmake_minimum_required(VERSION 3.16)
project(agentgate_phase5b LANGUAGES C CXX)

include(CTest)

set(AGENTGATE_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/../packages/ffi/include"
    CACHE PATH "Directory containing agentgate.h")
set(AGENTGATE_LIBRARY "" CACHE FILEPATH "Exact AgentGate native link library")
set(AGENTGATE_RUNTIME_LIBRARY "" CACHE FILEPATH
    "AgentGate runtime DLL when AGENTGATE_LIBRARY is a Windows import library")
option(AGENTGATE_STATIC "Link the AgentGate static library" OFF)

if(NOT EXISTS "${AGENTGATE_INCLUDE_DIR}/agentgate.h")
  message(FATAL_ERROR "AGENTGATE_INCLUDE_DIR does not contain agentgate.h")
endif()
if(NOT AGENTGATE_LIBRARY OR NOT EXISTS "${AGENTGATE_LIBRARY}")
  message(FATAL_ERROR "AGENTGATE_LIBRARY must name an existing native library")
endif()

if(AGENTGATE_STATIC)
  add_library(agentgate_ffi STATIC IMPORTED GLOBAL)
  target_compile_definitions(agentgate_ffi INTERFACE AGENTGATE_STATIC)
else()
  add_library(agentgate_ffi SHARED IMPORTED GLOBAL)
endif()

if(WIN32 AND NOT MSVC)
  message(FATAL_ERROR "Phase 5B Windows native targets require MSVC")
endif()

set_target_properties(agentgate_ffi PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES "${AGENTGATE_INCLUDE_DIR}")
if(WIN32 AND NOT AGENTGATE_STATIC)
  if(NOT AGENTGATE_RUNTIME_LIBRARY OR NOT EXISTS "${AGENTGATE_RUNTIME_LIBRARY}")
    message(FATAL_ERROR
      "AGENTGATE_RUNTIME_LIBRARY must name the AgentGate runtime DLL")
  endif()
  set_target_properties(agentgate_ffi PROPERTIES IMPORTED_IMPLIB "${AGENTGATE_LIBRARY}")
  set_target_properties(agentgate_ffi PROPERTIES
    IMPORTED_LOCATION "${AGENTGATE_RUNTIME_LIBRARY}")
else()
  set_target_properties(agentgate_ffi PROPERTIES IMPORTED_LOCATION "${AGENTGATE_LIBRARY}")
endif()

add_subdirectory(c)
add_subdirectory(cpp)
