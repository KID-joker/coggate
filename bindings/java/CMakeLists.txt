cmake_minimum_required(VERSION 3.20)
project(agentgate_java_jni LANGUAGES CXX)

include(CTest)
find_package(JNI REQUIRED)

set(AGENTGATE_INCLUDE_DIR "" CACHE PATH "Directory containing agentgate.h")
set(AGENTGATE_LIBRARY "" CACHE FILEPATH "AgentGate native link library")
set(AGENTGATE_RUNTIME_LIBRARY "" CACHE FILEPATH "Optional AgentGate runtime DLL/dylib")
set(AGENTGATE_MAVEN_REPOSITORY "${CMAKE_BINARY_DIR}/m2" CACHE PATH
    "Isolated Maven local repository used by CTest")

if(NOT EXISTS "${AGENTGATE_INCLUDE_DIR}/agentgate.h")
  message(FATAL_ERROR "AGENTGATE_INCLUDE_DIR must contain agentgate.h")
endif()
if(NOT EXISTS "${AGENTGATE_LIBRARY}")
  message(FATAL_ERROR "AGENTGATE_LIBRARY must name the AgentGate link library")
endif()

add_library(agentgate_jni SHARED src/main/cpp/agentgate_jni.cpp)
target_compile_features(agentgate_jni PRIVATE cxx_std_17)
target_include_directories(agentgate_jni PRIVATE "${AGENTGATE_INCLUDE_DIR}" ${JNI_INCLUDE_DIRS})
target_link_libraries(agentgate_jni PRIVATE "${AGENTGATE_LIBRARY}" ${JNI_LIBRARIES})
set_target_properties(agentgate_jni PROPERTIES
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)

if(MSVC)
  target_compile_options(agentgate_jni PRIVATE /W4 /WX /EHsc)
else()
  target_compile_options(agentgate_jni PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

get_filename_component(AGENTGATE_LIBRARY_DIRECTORY "${AGENTGATE_LIBRARY}" DIRECTORY)
if(APPLE)
  set_target_properties(agentgate_jni PROPERTIES
    BUILD_RPATH "${AGENTGATE_LIBRARY_DIRECTORY}"
    INSTALL_RPATH "@loader_path")
elseif(UNIX)
  set_target_properties(agentgate_jni PROPERTIES
    BUILD_RPATH "${AGENTGATE_LIBRARY_DIRECTORY}"
    INSTALL_RPATH "$ORIGIN")
endif()

if(WIN32 AND AGENTGATE_RUNTIME_LIBRARY)
  if(NOT EXISTS "${AGENTGATE_RUNTIME_LIBRARY}")
    message(FATAL_ERROR "AGENTGATE_RUNTIME_LIBRARY does not exist")
  endif()
  add_custom_command(TARGET agentgate_jni POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${AGENTGATE_RUNTIME_LIBRARY}" "$<TARGET_FILE_DIR:agentgate_jni>"
    VERBATIM)
endif()

if(BUILD_TESTING)
  find_program(MAVEN_EXECUTABLE NAMES mvn mvn.cmd)
  if(MAVEN_EXECUTABLE)
    add_test(NAME java_maven_tests
      COMMAND "${MAVEN_EXECUTABLE}" -q
        "-Dmaven.repo.local=${AGENTGATE_MAVEN_REPOSITORY}"
        "-Dagentgate.jni.path=$<TARGET_FILE:agentgate_jni>" test)
    set_tests_properties(java_maven_tests PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
  else()
    message(WARNING "Maven not found; java_maven_tests is not registered")
  endif()
endif()
