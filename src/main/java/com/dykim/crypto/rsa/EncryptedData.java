package com.dykim.crypto.rsa;

import lombok.AllArgsConstructor;
import lombok.Getter;

import java.security.PrivateKey;
import java.security.PublicKey;

@Getter
@AllArgsConstructor
class EncryptedData {
    String username;
    String password;
    PublicKey publicKey;
    PrivateKey privateKey;
}