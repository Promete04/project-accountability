#pragma once

#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <crypto++/cryptlib.h>
#include <crypto++/filters.h>
#include <crypto++/hex.h>
#include <crypto++/integer.h>
#include <crypto++/misc.h>
#include <crypto++/sha.h>

// String <=> Vec<char>.
std::string chvec2str(std::vector<unsigned char> data);
std::vector<unsigned char> str2chvec(std::string s);

// SecByteBlock <=> Integer.
CryptoPP::Integer byteblock_to_integer(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock integer_to_byteblock(const CryptoPP::Integer &x);

// SecByteBlock <=> string.
std::string byteblock_to_string(const CryptoPP::SecByteBlock &block);
CryptoPP::SecByteBlock string_to_byteblock(const std::string &s);

// Integer <=> string.
std::string integer_to_string(CryptoPP::Integer x);
CryptoPP::Integer string_to_integer(const std::string &s);

// Printers.
void print_string_as_hex(std::string str);
void print_key_as_int(const CryptoPP::SecByteBlock &block);
void print_key_as_hex(const CryptoPP::SecByteBlock &block);

// Splitter.
std::vector<std::string> string_split(std::string str, char delimiter);

// Hasher.
CryptoPP::Integer hash_dec_zkp(CryptoPP::Integer pk, CryptoPP::Integer a,
                               CryptoPP::Integer b, CryptoPP::Integer u,
                               CryptoPP::Integer v);
