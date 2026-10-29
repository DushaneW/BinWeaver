if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang" OR MINGW OR MSVC)
  message(FATAL_ERROR "BINWEAVER_FUZZ requires Clang with libFuzzer on Linux or macOS (MinGW and MSVC targets are unsupported). Use binweaver-replay elsewhere.")
endif()

add_executable(binweaver-fuzz fuzz_analyze.cpp)
target_link_libraries(binweaver-fuzz PRIVATE binweaver_core)
target_compile_options(binweaver-fuzz PRIVATE -fsanitize=fuzzer)
target_link_options(binweaver-fuzz PRIVATE -fsanitize=fuzzer)
# The core library needs coverage instrumentation too, otherwise libFuzzer
# only sees the harness.
target_compile_options(binweaver_core PRIVATE -fsanitize=fuzzer-no-link)
