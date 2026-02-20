file(GLOB_RECURSE SRC_FILES CONFIGURE_DEPENDS
  *.cpp
  *.hpp
)

add_library(emulator-common ${SRC_FILES})

momo_assign_source_group(${SRC_FILES})

target_include_directories(emulator-common INTERFACE "${CMAKE_CURRENT_LIST_DIR}")

set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)

target_link_libraries(emulator-common PUBLIC
  Threads::Threads
  ZLIB::ZLIB
  libzstd_static
  minidump::minidump
)

if(WIN)
  target_link_libraries(emulator-common PUBLIC
    ws2_32
  )
endif()
