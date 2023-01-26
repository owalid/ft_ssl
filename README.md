<div align="center">
  <img height="500px" src="https://user-images.githubusercontent.com/28403617/214816333-8eb0d620-d550-4de5-bf9f-20e70de6c010.svg#gh-light-mode-only">
  <img height="500px" src="https://user-images.githubusercontent.com/28403617/214816435-826743cc-d7b5-499d-b274-43cd246d96a6.svg#gh-dark-mode-only">
</div>

## [42 cursus] An introduction to cryptographic hashing algorithms

# Usage

```
Usage: ft_ssl algorithm [options] [file...]

Message Digest commands:
md5, sha224, sha256, sha384, sha512.

Cipher commands:
base64, des, des-ecb, des-cbc

Message Digest options:
Output options: 
-r      Reverse the format of the output.
-p      Echo STDIN to STDOUT and append the checksum to STDOUT.
-q      Quiet mode.
-s      Print the sum of the given string.
Parameters:
file Files to digest (optional; default is stdin).


Cipher options:
-a         Decode/encode the input/output in base64, depending on the encrypt mode.
-d         Decrypt mode.
-e         Encrypt mode (default).
-i         Input file for message.
-o         Output file for message.
-p         Password in ascii is the next argument.
-P         Print the iv/key and exit.
-s         The salt in hex is the next argument.
-iter +int Specify the iteration count. (default 4096)
-v         Initialization vector in hex is the next argument.

General options: 
-help   Display this summary
-list   List digests
```

# DES

## Legend

<img src="https://user-images.githubusercontent.com/28403617/213419800-d5e2e6a2-2a05-48ce-ae80-10be0756729e.png" align="center" />

## Key generation

<img src="https://user-images.githubusercontent.com/28403617/214658874-4324cb78-2647-4ba2-ad27-7511662d7f15.png" />

## Encryption loop

<img src="https://user-images.githubusercontent.com/28403617/213419908-23ea6121-2be4-49f3-9af6-c96b8cf91975.png" />

## F function from encryption loop

<img src="https://user-images.githubusercontent.com/28403617/213419874-3fa99277-0c28-4c49-b37d-b35669320977.png" />



## Source

- [Block cipher mode of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)
- [Wiki des](https://en.wikipedia.org/wiki/Data_Encryption_Standard)
- [Wiki b64](https://en.wikipedia.org/wiki/Base64)
- [Wiki Hmac](https://en.wikipedia.org/wiki/HMAC)
- [Wiki pbkdf](https://fr.wikipedia.org/wiki/PBKDF2)
- [scaler des](https://www.scaler.com/topics/des-algorithm/)
