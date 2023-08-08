# CMake version.
cmake_minimum_required(VERSION "3.26.3")

# Modules.
include("FetchContent")

# Project.
project("test_packio")

# Find libs.
find_package("Boost" REQUIRED "system" "url" "json")
find_package("fmt" REQUIRED)
find_package("OpenSSL" REQUIRED)

# [PackIO] - Download.
FetchContent_Populate("packio_package" URL "https://github.com/qchateau/packio/archive/master.zip")

# [Imgui] - Make library.
add_library("packio" INTERFACE)

# [PackIO] - Add includes.
target_include_directories("packio" INTERFACE
	"${packio_package_SOURCE_DIR}/include"
)

# [PackIO] - Linkage.
target_link_libraries("packio" INTERFACE
	Boost::system
	Boost::json
)

# Find sources.
file(GLOB_RECURSE src_server "src/server/*")
file(GLOB_RECURSE src_client "src/client/*")

# [Target] - Make.
add_executable("server" ${src_server})
add_executable("client" ${src_client})

# [Target] - Properties.
set_property(TARGET "server" PROPERTY CXX_STANDARD 23)
set_property(TARGET "server" PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET "server" PROPERTY CMAKE_CXX_EXTENSIONS OFF)
set_property(TARGET "client" PROPERTY CXX_STANDARD 23)
set_property(TARGET "client" PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET "client" PROPERTY CMAKE_CXX_EXTENSIONS OFF)

# [Target] - Linking.
target_link_libraries("server" PRIVATE
	Boost::system
	Boost::url
	fmt::fmt
	OpenSSL::SSL
	OpenSSL::Crypto
	ws2_32
	wsock32
	packio
)
target_link_libraries("client" PRIVATE
	Boost::system
	Boost::url
	fmt::fmt
	OpenSSL::SSL
	OpenSSL::Crypto
	ws2_32
	wsock32
	packio
)

# [Target] - Includes.
target_include_directories("server" PRIVATE "src/server")
target_include_directories("client" PRIVATE "src/client")

# [Target] - Macros.
target_compile_definitions("server" PRIVATE BOOST_ASIO_NO_DEPRECATED BOOST_ASIO_HAS_CO_AWAIT)
target_compile_definitions("client" PRIVATE BOOST_ASIO_NO_DEPRECATED BOOST_ASIO_HAS_CO_AWAIT)

# [Clang] - Enable LTO optimization.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(LLVM_ENABLE_LTO "Thin")
endif()

# [MSVC] - Enable big objects support.
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	target_compile_options("server" PRIVATE "/bigobj")
	target_compile_options("client" PRIVATE "/bigobj")
endif()

# [Windows] - Set minimal api version.
if(WIN32)
	target_compile_definitions("server" PRIVATE _WIN32_WINNT=0x0601)
	target_compile_definitions("client" PRIVATE _WIN32_WINNT=0x0601)
endif()

# Set msvc runtime library.
set_property(TARGET "server" PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_property(TARGET "client" PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
