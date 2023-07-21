package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import com.uid2.enclave.IAttestationProvider;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class OidcAttestationProvider implements IAttestationProvider {
	// the local file contains OIDC token
	private String tokenFilePath;
	private static final String DefaultTokenFilePath = "/run/container_launcher/attestation_verifier_claims_token";
	
	public OidcAttestationProvider() {
		this(DefaultTokenFilePath);
	}
	
	public OidcAttestationProvider(String tokenFilePath) {
		this.tokenFilePath = tokenFilePath;
	}

	@Override
	public byte[] getAttestationRequest(@SuppressWarnings("unused") byte[] publicKey) throws AttestationException {
		String token = null;
		try {
			token = new String(Files.readAllBytes(Paths.get(tokenFilePath)));
		} catch (IOException e) {
			throw new AttestationException(e);
		}
		if (token.isEmpty()) {
			throw new AttestationException("Token is empty");
		}
		return token.getBytes(StandardCharsets.US_ASCII);
	}
}
