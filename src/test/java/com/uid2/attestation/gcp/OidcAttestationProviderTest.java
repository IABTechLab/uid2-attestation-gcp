package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import org.junit.Assert;
import org.junit.Test;

import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;

public class OidcAttestationProviderTest {
	
	private String getResourcePath(String name) {
		try {
			return Paths.get(OidcAttestationProviderTest.class.getResource(name).toURI()).toFile().getAbsolutePath();
		} catch (URISyntaxException e) {
			return null;
		}
	}

	@Test
	public void testIsReadySuccess() {
		final long expirationInToken = 1509650801;
		final OidcAttestationProvider provider = new OidcAttestationProvider(
				getResourcePath("/com.uid2.attestation.gcp/test/OidcTokenValidJwt.txt"),
				expirationInToken - Instant.now().getEpochSecond() - 10 /* arbitrary number to pass readiness check */);
		Assert.assertTrue(provider.isReady());
	}

	@Test
	public void testIsReadyFailure_Expired() {
		final long expirationInToken = 1509650801;
		final OidcAttestationProvider provider = new OidcAttestationProvider(
				getResourcePath("/com.uid2.attestation.gcp/test/OidcTokenValidJwt.txt"),
				expirationInToken - Instant.now().getEpochSecond() + 10 /* arbitrary number to fail readiness check */);
		Assert.assertFalse(provider.isReady());
	}

	@Test
	public void testIsReadyFailure_FileNotExist() {
		final OidcAttestationProvider provider = new OidcAttestationProvider("/com.uid2.attestation.gcp/test/OidcToken_non_exist", 0);
		Assert.assertFalse(provider.isReady());
	}
	
	@Test
	public void testLoadTokenFileSuccess() throws AttestationException {
		final OidcAttestationProvider provider = new OidcAttestationProvider(getResourcePath("/com.uid2.attestation.gcp/test/OidcToken.txt"));
		byte[] output = provider.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 });
		String outputString = new String(output, StandardCharsets.US_ASCII);
		Assert.assertEquals("oidc.token", outputString);
	}
	
	@Test
	public void testLoadTokenFileFailure_FileNotExist() {
		final OidcAttestationProvider provider = new OidcAttestationProvider("/com.uid2.attestation.gcp/test/OidcToken_non_exist");
		Assert.assertThrows(AttestationException.class, ()-> provider.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 }));

		final OidcAttestationProvider providerDefaultPath = new OidcAttestationProvider();
		Assert.assertThrows(AttestationException.class, ()-> providerDefaultPath.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 }));
	}
	
	@Test
	public void testLoadTokenFileFailure_Empty() {
		final OidcAttestationProvider provider = new OidcAttestationProvider(getResourcePath("/com.uid2.attestation.gcp/test/OidcTokenEmpty.txt"));
		Assert.assertThrows(AttestationException.class, ()-> provider.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 }));
	}
}
