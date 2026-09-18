find_package(Threads REQUIRED)
get_filename_component(COGGATE_BINDING_FIXTURE_PATH_VALUE
  "${PROJECT_SOURCE_DIR}/../fixtures/bindings/v1.json" ABSOLUTE)
file(TO_CMAKE_PATH "${COGGATE_BINDING_FIXTURE_PATH_VALUE}"
  COGGATE_BINDING_FIXTURE_PATH_VALUE)

function(coggate_configure_cpp_target target source)
  add_executable(${target} "${source}" ${ARGN})
  target_link_libraries(${target} PRIVATE
    coggate_ffi
    nlohmann_json::nlohmann_json
    Threads::Threads)
  target_include_directories(${target} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
  target_compile_definitions(${target} PRIVATE
    COGGATE_BINDING_FIXTURE_PATH="${COGGATE_BINDING_FIXTURE_PATH_VALUE}")
  if(WIN32 AND NOT COGGATE_STATIC)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:coggate_ffi>" "$<TARGET_FILE_DIR:${target}>")
  endif()
  set_target_properties(${target} PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED YES
    CXX_EXTENSIONS NO)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  add_test(NAME ${target} COMMAND ${target})
endfunction()

file(GLOB COGGATE_CPP_TEST_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
file(GLOB COGGATE_CPP_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/harness.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_support.cpp")
file(GLOB COGGATE_CPP_EXAMPLE_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/harness.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*_support.cpp")
list(REMOVE_ITEM COGGATE_CPP_TEST_SOURCES ${COGGATE_CPP_TEST_SUPPORT_SOURCES})
foreach(source IN LISTS COGGATE_CPP_TEST_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  coggate_configure_cpp_target("coggate_cpp_test_${stem}" "${source}"
    ${COGGATE_CPP_TEST_SUPPORT_SOURCES})
endforeach()

file(GLOB COGGATE_CPP_EXAMPLE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
list(REMOVE_ITEM COGGATE_CPP_EXAMPLE_SOURCES ${COGGATE_CPP_EXAMPLE_SUPPORT_SOURCES})
foreach(source IN LISTS COGGATE_CPP_EXAMPLE_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  coggate_configure_cpp_target("coggate_cpp_example_${stem}" "${source}"
    ${COGGATE_CPP_EXAMPLE_SUPPORT_SOURCES})
endforeach()
