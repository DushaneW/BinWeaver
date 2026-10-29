#include "binweaver/binweaver.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>
int main(){using namespace bw;assert(sha256(std::span<const std::uint8_t>{})=="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");std::vector<std::uint8_t> z(128);assert(entropy(z)==0.0);std::vector<std::uint8_t> all(256);for(int i=0;i<256;++i)all[static_cast<std::size_t>(i)]=static_cast<std::uint8_t>(i);assert(entropy(all)>7.99);
 auto p=std::filesystem::temp_directory_path()/"bw-bad-pe.bin";{std::ofstream f(p,std::ios::binary);f<<"MZ\0\0";}auto a=analyze(p);assert(a.format==Format::PE&&!a.structurally_valid&&!a.diagnostics.empty());std::filesystem::remove(p);std::cout<<"Tests passed\n";}
