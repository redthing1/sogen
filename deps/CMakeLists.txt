set(UNICORN_ARCH "x86" CACHE STRING "")
add_subdirectory(unicorn)

##########################################

option(BASE64_ENABLE_TESTING "" OFF)
add_subdirectory(base64)

##########################################

option(FLATBUFFERS_BUILD_TESTS "" OFF)
option(FLATBUFFERS_INSTALL "" OFF)
add_subdirectory(flatbuffers)

if(MSVC)
target_compile_options(flatc PRIVATE /MD$<$<CONFIG:Debug>:d>)
endif()

##########################################

add_library(reflect INTERFACE)
target_include_directories(reflect INTERFACE
    "${CMAKE_CURRENT_LIST_DIR}/reflect"
)

##########################################

option(BUILD_PARSER "" OFF)
option(BUILD_PYTHON_BINDING "" OFF)
add_subdirectory(udmp-parser/src)

##########################################

include(googletest.cmake)
include(zlib.cmake)
