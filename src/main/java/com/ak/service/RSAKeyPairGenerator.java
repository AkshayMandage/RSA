package com.ak.service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.springframework.stereotype.Service;

@Service
public class RSAKeyPairGenerator {

	private KeyPairGenerator keyPairGenerator;

	public RSAKeyPairGenerator() throws NoSuchAlgorithmException {
		this.keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		this.keyPairGenerator.initialize(2048); // Key size 2048 bits
	}

	public KeyPair generateKeyPair() {
		return this.keyPairGenerator.generateKeyPair();
	}
}
