package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import com.uid2.enclave.IAttestationProvider;

import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.json.webtoken.JsonWebSignature;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;

public class OidcAttestationProvider implements IAttestationProvider {
	private static final Logger LOGGER = LoggerFactory.getLogger(OidcAttestationProvider.class);

	// the local file contains OIDC token
	private final String tokenFilePath;
	private static final String DefaultTokenFilePath = "/run/container_launcher/attestation_verifier_claims_token";
	private final long expirationThresholdSeconds;
	private static final long DefaultExpirationThresholdSeconds = 60;
	
	public OidcAttestationProvider() {
		this(DefaultTokenFilePath);
	}

	public OidcAttestationProvider(String tokenFilePath) {
		this(tokenFilePath, DefaultExpirationThresholdSeconds);
	}

	public OidcAttestationProvider(String tokenFilePath, long expirationThresholdSeconds) {
		this.tokenFilePath = tokenFilePath;
		this.expirationThresholdSeconds = expirationThresholdSeconds;
	}

	@Override
	public boolean isReady() {
		try {
			String token = new String(Files.readAllBytes(Paths.get(tokenFilePath)));
			JsonWebSignature signature = JsonWebSignature.parse(GsonFactory.getDefaultInstance(), token);
			Instant expiredAt = Instant.ofEpochSecond(signature.getPayload().getExpirationTimeSeconds());

			long secondsToExpire = Duration.between(Instant.now(), expiredAt).getSeconds();
			if (secondsToExpire >= expirationThresholdSeconds) {
				return true;
			}
			LOGGER.warn("OIDC token to expire in " + secondsToExpire + " seconds");
		} catch (IOException e) {
			LOGGER.warn("Failed to load or parse OIDC token: " + e.getMessage());
		} catch (DateTimeException e) {
			LOGGER.warn("Failed to parse OIDC token expiration time: " + e.getMessage());
		} catch (Exception e) {
			LOGGER.warn("Failed to check OIDC token readiness: " + e.getMessage());
		}

		return false;
	}

	@Override
	public byte[] getAttestationRequest(@SuppressWarnings("unused") byte[] publicKey, byte[] userData) throws AttestationException {
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
