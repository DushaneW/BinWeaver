cmake_minimum_required(VERSION 3.20)
project(BinWeaver VERSION 0.7.0 LANGUAGES CXX)

option(BINWEAVER_BUILD_GUI "Build the Qt 6 desktop UI" OFF)
option(BINWEAVER_BUILD_TESTS "Build tests" ON)
option(BINWEAVER_BUILD_BENCH "Build the benchmark tool" OFF)
option(BINWEAVER_FUZZ "Build libFuzzer harnesses (Clang only)" OFF)
option(BINWEAVER_WERROR "Treat compiler warnings as errors" OFF)
set(BINWEAVER_SANITIZE "" CACHE STRING "Sanitizers for GCC/Clang, e.g. 'address;undefined'")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(BINWEAVER_SANITIZE AND NOT MSVC)
  string(REPLACE ";" "," _bw_san "${BINWEAVER_SANITIZE}")
  add_compile_options(-fsanitize=${_bw_san} -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=${_bw_san})
endif()

function(binweaver_warnings target)
  if(MSVC)
    target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    if(BINWEAVER_WERROR)
      target_compile_options(${target} PRIVATE /WX)
    endif()
  else()
    target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow)
    if(BINWEAVER_WERROR)
      target_compile_options(${target} PRIVATE -Werror)
    endif()
  endif()
endfunction()

add_library(binweaver_core
  src/analyzer.cpp
  src/authenticode.cpp
  src/diagnostics.cpp
  src/diff.cpp
  src/dotnet.cpp
  src/elf.cpp
  src/fields.cpp
  src/file_image.cpp
  src/hash.cpp
  src/icons.cpp
  src/heuristics.cpp
  src/metrics.cpp
  src/model.cpp
  src/ordinal_names.cpp
  src/pe.cpp
  src/report.cpp
  src/rules.cpp)
target_include_directories(binweaver_core PUBLIC include)
binweaver_warnings(binweaver_core)

add_executable(binweaver-cli src/cli.cpp)
target_link_libraries(binweaver-cli PRIVATE binweaver_core)
binweaver_warnings(binweaver-cli)

# Examples are built by default so API changes cannot silently break them.
add_executable(binweaver-hardening-check examples/hardening_check.cpp)
target_link_libraries(binweaver-hardening-check PRIVATE binweaver_core)
add_executable(binweaver-deps examples/dependency_list.cpp)
target_link_libraries(binweaver-deps PRIVATE binweaver_core)
binweaver_warnings(binweaver-hardening-check)
binweaver_warnings(binweaver-deps)

# MinGW: link the command-line tools statically so they run without the
# toolchain's libc++/libunwind DLLs on PATH. (Not combined with sanitizers,
# whose runtimes are DLLs.)
if(MINGW AND NOT BINWEAVER_SANITIZE)
  foreach(tool binweaver-cli binweaver-hardening-check binweaver-deps)
    target_link_options(${tool} PRIVATE -static)
  endforeach()
endif()

if(BINWEAVER_BUILD_GUI)
  find_package(Qt6 6.4 REQUIRED COMPONENTS Widgets Concurrent)
  qt_standard_project_setup()
  # The UI is a library so the GUI tests exercise exactly the shipped code.
  qt_add_library(binweaver_gui STATIC
    src/gui/main_window.cpp src/gui/main_window.hpp
    src/gui/hex_view.cpp src/gui/hex_view.hpp
    src/gui/entropy_view.cpp src/gui/entropy_view.hpp
    src/gui/table_model.cpp src/gui/table_model.hpp
    src/gui/compare_window.cpp src/gui/compare_window.hpp
    src/gui/document.cpp src/gui/document.hpp)
  target_include_directories(binweaver_gui PUBLIC src/gui)
  target_compile_definitions(binweaver_gui PUBLIC BINWEAVER_VERSION="${PROJECT_VERSION}")
  target_link_libraries(binweaver_gui PUBLIC binweaver_core Qt6::Widgets Qt6::Concurrent)
  binweaver_warnings(binweaver_gui)
  qt_add_executable(binweaver WIN32 src/gui/main.cpp)
  target_link_libraries(binweaver PRIVATE binweaver_gui)
  binweaver_warnings(binweaver)
endif()

if(BINWEAVER_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

if(BINWEAVER_BUILD_BENCH)
  add_executable(binweaver-bench bench/bench.cpp)
  target_link_libraries(binweaver-bench PRIVATE binweaver_core)
  binweaver_warnings(binweaver-bench)
endif()

if(BINWEAVER_FUZZ)
  add_subdirectory(fuzz)
endif()
