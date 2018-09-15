package com.dykim.crypto.rsa;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.commons.io.FileUtils;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.rsa.crypto.RsaRawEncryptor;

import java.io.File;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.List;

import static java.util.stream.Collectors.joining;

@SpringBootApplication
public class RsaApplication implements CommandLineRunner {

    public static void main(String[] args) {
        SpringApplication.run(RsaApplication.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        String username = "garlic_pepper_sandwich";
        String password = "john.wick";

        //enc
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair keyPair = generator.genKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        TextEncryptor encryptor = new RsaRawEncryptor("UTF-8", publicKey, privateKey);
        String encryptedUsername = encryptor.encrypt(username);
        String encryptedPassword = encryptor.encrypt(password);

        print(username, password, encryptedUsername, encryptedPassword);
        saveEncryptedData(encryptedUsername, encryptedPassword, publicKey, privateKey);

        //dec
        EncryptedData encryptedData = readEncryptedData();
        TextEncryptor decryptor = new RsaRawEncryptor("UTF-8", encryptedData.getPublicKey(), encryptedData.getPrivateKey());
        String decryptedUsername = decryptor.decrypt(encryptedData.getUsername());
        String decryptedPassword = decryptor.decrypt(encryptedData.getPassword());

        print(username, password, decryptedUsername, decryptedPassword);
    }

    private EncryptedData readEncryptedData() {
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

    private void saveEncryptedData(String encryptedUsername, String encryptedPassword, PublicKey publicKey, PrivateKey privateKey) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPublicKeySpec publicKeySpec = keyFactory.getKeySpec(publicKey, RSAPublicKeySpec.class);
            RSAPrivateKeySpec privateKeySpec = keyFactory.getKeySpec(privateKey, RSAPrivateKeySpec.class);
            FileUtils.writeLines(new File("./data.dic"),
                    Arrays.asList(encryptedUsername, encryptedPassword,
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

    public static void print(Object... o) {
        System.out.println(
                Arrays.stream(o).map(Object::toString).collect(joining(","))
        );
    }
}

@Getter
@AllArgsConstructor
class EncryptedData {
    String username;
    String password;
    PublicKey publicKey;
    PrivateKey privateKey;
}