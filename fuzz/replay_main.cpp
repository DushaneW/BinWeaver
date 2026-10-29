// Replays files or directories through the fuzz target without libFuzzer.
// Used by ctest for the committed corpus and for reproducing crashes on
// compilers that lack -fsanitize=fuzzer (MSVC, GCC).
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);

int main(int argc, char** argv) {
    std::size_t runs = 0;
    for (int i = 1; i < argc; ++i) {
        std::vector<std::filesystem::path> files;
        if (std::filesystem::is_directory(argv[i])) {
            for (const auto& e : std::filesystem::recursive_directory_iterator(argv[i]))
                if (e.is_regular_file()) files.push_back(e.path());
        } else {
            files.emplace_back(argv[i]);
        }
        for (const auto& p : files) {
            std::ifstream f(p, std::ios::binary);
            std::vector<std::uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
            LLVMFuzzerTestOneInput(data.data(), data.size());
            ++runs;
        }
    }
    std::cout << "replayed " << runs << " inputs\n";
    return runs ? 0 : 1;
}
