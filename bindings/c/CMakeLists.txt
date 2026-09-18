function(coggate_configure_c_target target source is_test)
  add_executable(${target} "${source}" ${ARGN})
  target_link_libraries(${target} PRIVATE coggate_ffi)
  if(WIN32 AND NOT COGGATE_STATIC)
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different
        "$<TARGET_FILE:coggate_ffi>" "$<TARGET_FILE_DIR:${target}>")
  endif()
  set_target_properties(${target} PROPERTIES
    C_STANDARD 11
    C_STANDARD_REQUIRED YES
    C_EXTENSIONS NO)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /WX)
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Werror)
  endif()
  if(is_test)
    add_test(NAME ${target} COMMAND ${target})
  endif()
endfunction()

file(GLOB COGGATE_C_TEST_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c")
file(GLOB COGGATE_C_TEST_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/harness.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/tests/*_support.c")
file(GLOB COGGATE_C_EXAMPLE_SUPPORT_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/harness.c"
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*_support.c")
list(REMOVE_ITEM COGGATE_C_TEST_SOURCES ${COGGATE_C_TEST_SUPPORT_SOURCES})
foreach(source IN LISTS COGGATE_C_TEST_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  coggate_configure_c_target("coggate_c_test_${stem}" "${source}" TRUE
    ${COGGATE_C_TEST_SUPPORT_SOURCES})
endforeach()

file(GLOB COGGATE_C_EXAMPLE_SOURCES CONFIGURE_DEPENDS
  "${CMAKE_CURRENT_SOURCE_DIR}/examples/*.c")
list(REMOVE_ITEM COGGATE_C_EXAMPLE_SOURCES ${COGGATE_C_EXAMPLE_SUPPORT_SOURCES})
foreach(source IN LISTS COGGATE_C_EXAMPLE_SOURCES)
  get_filename_component(stem "${source}" NAME_WE)
  coggate_configure_c_target("coggate_c_example_${stem}" "${source}" TRUE
    ${COGGATE_C_EXAMPLE_SUPPORT_SOURCES})
endforeach()
