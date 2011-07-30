project(upload_s3)
cmake_minimum_required(VERSION 2.6)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)

find_package(LibXml2 REQUIRED)
include_directories(${LIBXML2_INCLUDE_DIR})

INCLUDE(FindPkgConfig)

pkg_search_module(GLIB2 REQUIRED glib-2.0)
include_directories(${GLIB2_INCLUDE_DIRS})

add_executable(upload_s3 main.cpp)

target_link_libraries(upload_s3
  ${OPENSSL_LIBRARIES}
  ${OPENSSL_EXTRA_LIBRARIES}
  ${CURL_LIBRARIES}
  ${LIBXML2_LIBRARIES}
  ${GLIB2_LIBRARIES}
)

INSTALL_PROGRAMS(/bin FILES upload_s3)
