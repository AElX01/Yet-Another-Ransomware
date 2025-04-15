#pragma once
#include <windows.h>
#include <winhttp.h>
#include <tchar.h>
#include <vector>
#include <iostream>
#include <string>

#pragma comment(lib, "winhttp.lib")


boolean c2_handler(std::vector<BYTE>& key, const std::vector<BYTE>& inputData_1);