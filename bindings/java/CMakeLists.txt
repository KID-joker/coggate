cmake_minimum_required(VERSION 3.20)
project(coggate_java_jni LANGUAGES CXX)

include(CTest)
find_package(JNI REQUIRED)

set(COGGATE_INCLUDE_DIR "" CACHE PATH "Directory containing coggate.h")
set(COGGATE_LIBRARY "" CACHE FILEPATH "CogGate native link library")
set(COGGATE_RUNTIME_LIBRARY "" CACHE FILEPATH "Optional CogGate runtime DLL/dylib")
option(COGGATE_STATIC_LINK "Link CogGate into the JNI shim statically" OFF)
set(COGGATE_MAVEN_REPOSITORY "${CMAKE_BINARY_DIR}/m2" CACHE PATH
    "Isolated Maven local repository used by CTest")

if(NOT EXISTS "${COGGATE_INCLUDE_DIR}/coggate.h")
  message(FATAL_ERROR "COGGATE_INCLUDE_DIR must contain coggate.h")
endif()
if(NOT EXISTS "${COGGATE_LIBRARY}")
  message(FATAL_ERROR "COGGATE_LIBRARY must name the CogGate link library")
endif()

add_library(coggate_jni SHARED src/main/cpp/coggate_jni.cpp)
target_compile_features(coggate_jni PRIVATE cxx_std_17)
target_include_directories(coggate_jni PRIVATE "${COGGATE_INCLUDE_DIR}" ${JNI_INCLUDE_DIRS})
target_link_libraries(coggate_jni PRIVATE "${COGGATE_LIBRARY}")
if(COGGATE_STATIC_LINK)
  target_compile_definitions(coggate_jni PRIVATE COGGATE_STATIC)
endif()
set_target_properties(coggate_jni PROPERTIES
  CXX_EXTENSIONS OFF
  POSITION_INDEPENDENT_CODE ON)

if(MSVC)
  target_compile_options(coggate_jni PRIVATE /W4 /WX /EHsc)
else()
  target_compile_options(coggate_jni PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

if(APPLE)
  set_target_properties(coggate_jni PROPERTIES
    BUILD_RPATH "@loader_path"
    INSTALL_RPATH "@loader_path")
elseif(UNIX)
  set_target_properties(coggate_jni PROPERTIES
    BUILD_RPATH "$ORIGIN"
    INSTALL_RPATH "$ORIGIN")
endif()

set(COGGATE_RUNTIME_SOURCE "")
if(WIN32 AND NOT COGGATE_STATIC_LINK)
  if(NOT COGGATE_RUNTIME_LIBRARY)
    message(FATAL_ERROR
      "COGGATE_RUNTIME_LIBRARY is required for a shared Windows build")
  endif()
  if(NOT EXISTS "${COGGATE_RUNTIME_LIBRARY}")
    message(FATAL_ERROR "COGGATE_RUNTIME_LIBRARY does not exist")
  endif()
  set(COGGATE_RUNTIME_SOURCE "${COGGATE_RUNTIME_LIBRARY}")
elseif(NOT COGGATE_STATIC_LINK AND COGGATE_RUNTIME_LIBRARY)
  if(NOT EXISTS "${COGGATE_RUNTIME_LIBRARY}")
    message(FATAL_ERROR "COGGATE_RUNTIME_LIBRARY does not exist")
  endif()
  set(COGGATE_RUNTIME_SOURCE "${COGGATE_RUNTIME_LIBRARY}")
elseif(NOT COGGATE_STATIC_LINK AND UNIX)
  set(COGGATE_RUNTIME_SOURCE "${COGGATE_LIBRARY}")
endif()

if(COGGATE_RUNTIME_SOURCE)
  add_custom_command(TARGET coggate_jni POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
      "${COGGATE_RUNTIME_SOURCE}" "$<TARGET_FILE_DIR:coggate_jni>"
    VERBATIM)
endif()

if(APPLE AND NOT COGGATE_STATIC_LINK)
  find_program(OTOOL_EXECUTABLE NAMES otool REQUIRED)
  find_program(INSTALL_NAME_TOOL_EXECUTABLE NAMES install_name_tool REQUIRED)
  execute_process(COMMAND "${OTOOL_EXECUTABLE}" -D "${COGGATE_LIBRARY}"
    RESULT_VARIABLE COGGATE_OTOOL_RESULT
    OUTPUT_VARIABLE COGGATE_OTOOL_OUTPUT
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT COGGATE_OTOOL_RESULT EQUAL 0)
    message(FATAL_ERROR "Unable to inspect CogGate dylib install name")
  endif()
  string(REPLACE "\n" ";" COGGATE_OTOOL_LINES "${COGGATE_OTOOL_OUTPUT}")
  list(GET COGGATE_OTOOL_LINES -1 COGGATE_INSTALL_NAME)
  get_filename_component(COGGATE_RUNTIME_BASENAME "${COGGATE_RUNTIME_SOURCE}" NAME)
  add_custom_command(TARGET coggate_jni POST_BUILD
    COMMAND "${INSTALL_NAME_TOOL_EXECUTABLE}" -change
      "${COGGATE_INSTALL_NAME}" "@rpath/${COGGATE_RUNTIME_BASENAME}"
      "$<TARGET_FILE:coggate_jni>"
    VERBATIM)
endif()

if(BUILD_TESTING)
  find_program(MAVEN_EXECUTABLE NAMES mvn mvn.cmd)
  if(MAVEN_EXECUTABLE)
    add_test(NAME java_maven_package
      COMMAND "${MAVEN_EXECUTABLE}" -q
        "-Dmaven.repo.local=${COGGATE_MAVEN_REPOSITORY}"
        "-Dcoggate.jni.path=$<TARGET_FILE:coggate_jni>" clean package)
    set_tests_properties(java_maven_package PROPERTIES
      WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
  else()
    message(WARNING "Maven not found; java_maven_package is not registered")
  endif()
endif()
