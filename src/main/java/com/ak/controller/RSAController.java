package com.ak.controller;

import java.security.KeyPair;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import com.ak.service.RSAEncryptionService;
import com.ak.service.RSAKeyPairGenerator;
import com.ak.util.Base64Util;

@RestController
@RequestMapping("/api/rsa")
public class RSAController {

	@Autowired
	private RSAKeyPairGenerator keyPairGenerator;

	@Autowired
	private RSAEncryptionService encryptionService;

	@GetMapping("/generate-keypair")
	public Map<String, String> generateKeyPair() {
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		// Convert keys to Base64 strings
		String publicKeyBase64 = Base64Util.encode(keyPair.getPublic().getEncoded());
		String privateKeyBase64 = Base64Util.encode(keyPair.getPrivate().getEncoded());

		Map<String, String> keyPairMap = new HashMap<>();
		keyPairMap.put("publicKey", publicKeyBase64);
		keyPairMap.put("privateKey", privateKeyBase64);

		return keyPairMap;
	}

	@PostMapping("/encrypt")
	public @ResponseBody String encrypt(@RequestBody String plaintext, @RequestParam String publicKey)
			throws Exception {
		byte[] encryptedData = encryptionService.encrypt(Base64Util.decode(publicKey), plaintext.getBytes());
		return Base64Util.encode(encryptedData);
	}

	@PostMapping("/decrypt")
	public @ResponseBody String decrypt(@RequestBody String encryptedText, @RequestParam String privateKey)
			throws Exception {
		byte[] decryptedData = encryptionService.decrypt(Base64Util.decode(privateKey),
				Base64Util.decode(encryptedText));
		return new String(decryptedData);
	}
}
