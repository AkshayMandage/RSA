package com.ak.service;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

@Service
public class RSAEncryptionService {

	private Cipher cipher;

	public RSAEncryptionService() throws NoSuchAlgorithmException, NoSuchPaddingException {
		Security.addProvider(new BouncyCastleProvider());
		this.cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	}

	public byte[] encrypt(byte[] publicKeyBytes, byte[] data) throws Exception {
		PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
		this.cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		return this.cipher.doFinal(data);
	}

	public byte[] decrypt(byte[] privateKeyBytes, byte[] encryptedData) throws Exception {
		PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
		this.cipher.init(Cipher.DECRYPT_MODE, privateKey);
		return this.cipher.doFinal(encryptedData);
	}
}
