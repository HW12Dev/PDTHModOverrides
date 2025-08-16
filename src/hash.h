#pragma once

#include <string>

unsigned long long hash64(char* k, unsigned long long length, unsigned long long level);
unsigned long long hash64(const std::string& s);