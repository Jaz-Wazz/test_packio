# CMake version.
cmake_minimum_required(VERSION "3.26.3")

# Modules.
include("FetchContent")

# Project.
project("test_packio")

# Find libs.
find_package("Boost" REQUIRED "system" "url")
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
)

# Find sources.
file(GLOB_RECURSE src "src/*")

# [Target] - Make.
add_executable(${PROJECT_NAME} ${src})

# [Target] - Properties.
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 23)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CMAKE_CXX_EXTENSIONS OFF)

# [Target] - Linking.
target_link_libraries(${PROJECT_NAME} PRIVATE
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
target_include_directories(${PROJECT_NAME} PRIVATE "src")

# [Target] - Macros.
target_compile_definitions(${PROJECT_NAME} PRIVATE BOOST_ASIO_NO_DEPRECATED BOOST_ASIO_HAS_CO_AWAIT)

# [Clang] - Enable LTO optimization.
if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
	set(LLVM_ENABLE_LTO "Thin")
endif()

# [MSVC] - Enable big objects support.
if (CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
	target_compile_options(${PROJECT_NAME} PRIVATE "/bigobj")
endif()

# [Windows] - Set minimal api version.
if(WIN32)
	target_compile_definitions(${PROJECT_NAME} PRIVATE _WIN32_WINNT=0x0601)
endif()

# Set msvc runtime library.
set_property(TARGET ${PROJECT_NAME} PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
