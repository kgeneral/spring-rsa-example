package com.dykim.crypto.rsa;

import org.omg.CosNaming.NamingContextExtPackage.StringNameHelper;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.rsa.crypto.RsaRawEncryptor;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import static java.lang.String.join;
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

        RsaRawEncryptor encryptor = new RsaRawEncryptor("UTF-8",publicKey, privateKey);
        String encryptedUsername = encryptor.encrypt(username);
        String encryptedPassword = encryptor.encrypt(password);

        print(username, password, encryptedUsername, encryptedPassword);

        //dec
        RsaRawEncryptor decryptor = new RsaRawEncryptor("UTF-8",publicKey, privateKey);
        String decryptedUsername = decryptor.decrypt(encryptedUsername);
        String decryptedPassword = decryptor.decrypt(encryptedPassword);

        print(username, password, decryptedUsername, decryptedPassword);


    }

    public static void print(Object... o){
        System.out.println(
                Arrays.stream(o).map(Object::toString).collect(joining(","))
        );
    }
}
