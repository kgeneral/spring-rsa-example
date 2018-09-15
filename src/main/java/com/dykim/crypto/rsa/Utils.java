package com.dykim.crypto.rsa;

import java.util.Arrays;

import static java.util.stream.Collectors.joining;

public class Utils {
    public static void print(Object... o) {
        System.out.println(
                Arrays.stream(o).map(Object::toString).collect(joining(","))
        );
    }
}
