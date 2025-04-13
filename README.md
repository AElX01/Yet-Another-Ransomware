# yetAnotherRansomware (YAR)

A C++ ransomware that targets Windows systems using the CNG (Cryptography API: Next Generation) API for Windows. It will encrypt recursively all files under the current user's directory.

## features

- Usage of AES-128-CBC for file encryption
- Securing the AES key by encrypting it with an RSA 2048 bit key (harcoded in the code)
- Usage of an http server that contains the private key to decrypt the AES key, then decrypt files, the server can be found in my repo: [cpp-simpleHttpServer](https://github.com/AElX01/cpp-simpleHttpServer/tree/master)

## usage

```
.\yar.exe
```

## issues

- Lack of a gui to ask for the token, if the user closes the terminal, the program will terminate and files will remain encrypted
- Lack of advanced AV evasion techniques, still in early development stage