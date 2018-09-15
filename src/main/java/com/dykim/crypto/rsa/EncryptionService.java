package com.dykim.crypto.rsa;

import org.apache.commons.io.FileUtils;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.rsa.crypto.RsaRawEncryptor;

import java.io.File;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import static com.dykim.crypto.rsa.Utils.print;

public class EncryptionService {

    public void saveEncryptedData(EncryptedData encryptedData) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(encryptedData.getPublicKey(), RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(encryptedData.getPrivateKey(), RSAPrivateKeySpec.class);
            FileUtils.writeLines(new File("./data.dic"),
                    Arrays.asList(encryptedData.getUsername(), encryptedData.getPassword(),
                            publicKeySpec.getModulus().toString(16),
                            publicKeySpec.getPublicExponent().toString(16),
                            privateKeySpec.getModulus().toString(16),
                            privateKeySpec.getPrivateExponent().toString(16)
                    )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public EncryptedData readEncryptedData() {
        try {
            List<String> data = FileUtils.readLines(new File("./data.dic"), "UTF-8");

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = new RSAPublicKeySpec(
                    new BigInteger(data.get(2), 16), new BigInteger(data.get(3), 16)
            );
            RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(
                    new BigInteger(data.get(4), 16), new BigInteger(data.get(5), 16)
            );
            return new EncryptedData(
                    data.get(0),
                    data.get(1),
                    keyFactory.generatePublic(publicKeySpec),
                    keyFactory.generatePrivate(privateKeySpec)
            );

        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        EncryptionService encryptionService = new EncryptionService();
        EncryptedData encryptedData = encryptionService.readEncryptedData();

        TextEncryptor decryptor = new RsaRawEncryptor("UTF-8", encryptedData.getPublicKey(), encryptedData.getPrivateKey());

        print(
                decryptor.decrypt(encryptedData.getUsername()), decryptor.decrypt(encryptedData.getPassword())
        );
    }
}
