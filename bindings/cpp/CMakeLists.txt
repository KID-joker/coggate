function(agentgate_configure_cpp_target target source is_test)
  add_executable(${target} "${source}" ${ARGN})
  target_link_libraries(${target} PRIVATE
    agentgate_ffi
    nlohmann_json::nlohmann_json)
  target_include_directories(${target} PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include")
  if(WIN32 AND NOT AGENTGATE_STATIC)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:agentgate_ffi>" "$<TARGET_FILE_DIR:${target}>")
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
  if(is_test)
    add_test(NAME ${target} COMMAND ${target})
  endif()
endfunction()

file(GLOB AGENTGATE_CPP_TEST_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp")
file(GLOB AGENTGATE_CPP_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/harness.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_support.cpp")
file(GLOB AGENTGATE_CPP_EXAMPLE_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/harness.cpp"
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*_support.cpp")
list(REMOVE_ITEM AGENTGATE_CPP_TEST_SOURCES ${AGENTGATE_CPP_TEST_SUPPORT_SOURCES})
foreach(source IN LISTS AGENTGATE_CPP_TEST_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  agentgate_configure_cpp_target("agentgate_cpp_test_${stem}" "${source}" TRUE
    ${AGENTGATE_CPP_TEST_SUPPORT_SOURCES})
endforeach()

file(GLOB AGENTGATE_CPP_EXAMPLE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.cpp")
list(REMOVE_ITEM AGENTGATE_CPP_EXAMPLE_SOURCES ${AGENTGATE_CPP_EXAMPLE_SUPPORT_SOURCES})
foreach(source IN LISTS AGENTGATE_CPP_EXAMPLE_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  agentgate_configure_cpp_target("agentgate_cpp_example_${stem}" "${source}" FALSE
    ${AGENTGATE_CPP_EXAMPLE_SUPPORT_SOURCES})
endforeach()
