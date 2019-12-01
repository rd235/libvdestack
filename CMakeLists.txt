cmake_minimum_required(VERSION 3.1)
project("libvdestack"
    DESCRIPTION "A network namespace as a library, i.e. Internet of Threads through Network Namespaces."
    HOMEPAGE_URL "https://github.com/rd235/libvdestack"
    VERSION 0.1.0
    LANGUAGES C)

include(GNUInstallDirs)
include(CheckIncludeFile)

set(CMAKE_REQUIRED_QUIET TRUE)
set(LIBS_REQUIRED vdeplug cap execs)
set(HEADERS_REQUIRED libvdeplug.h sys/capability.h execs.h)

foreach(THISLIB IN LISTS LIBS_REQUIRED)
  find_library(LIB${THISLIB}_OK ${THISLIB})
  if(NOT LIB${THISLIB}_OK)
    message(FATAL_ERROR "library lib${THISLIB} not found")
  endif()
endforeach(THISLIB)

foreach(HEADER IN LISTS HEADERS_REQUIRED)
  check_include_file(${HEADER} ${HEADER}_OK)
  if(NOT ${HEADER}_OK)
    message(FATAL_ERROR "header file ${HEADER} not found")
  endif()
endforeach(HEADER)

add_definitions(-D_GNU_SOURCE)
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

add_library(vdestack SHARED vdestack.c)
target_link_libraries(vdestack -lcap -lexecs -lvdeplug)

set_target_properties(vdestack PROPERTIES VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR})

install(TARGETS vdestack DESTINATION ${CMAKE_INSTALL_LIBDIR})

#file(GLOB MAN3_PAGES ${CMAKE_CURRENT_SOURCE_DIR}/*.3)
#
#install(FILES ${MAN3_PAGES} DESTINATION ${CMAKE_INSTALL_MANDIR}/man3)
add_subdirectory(man)

add_custom_target(uninstall
  "${CMAKE_COMMAND}" -P "${PROJECT_SOURCE_DIR}/Uninstall.cmake")

