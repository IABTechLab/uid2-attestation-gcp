package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import org.junit.Assert;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

public class VmidAttestationProviderTest  {
	@Test
	public void testAgainstDebugHttpServer() throws AttestationException {
		final VmidAttestationProvider provider = new VmidAttestationProvider();
		provider.setMetadataEndpoint("https://httpbin.org/get");
		byte[] output = provider.getAttestationRequest(new byte[] { 0x01, 0x02, 0x03 }, new byte[] {0x04, 0x05});
		String outputString = new String(output, StandardCharsets.US_ASCII);
		System.out.println(outputString);

		// base64 of 0x01 0x02 0x03 is AQID
		Assert.assertTrue(outputString.contains("audience=AQID"));
		Assert.assertTrue(outputString.contains("format=full"));
		Assert.assertTrue(outputString.contains("https://httpbin.org/get?"));
		Assert.assertTrue(outputString.contains("Metadata-Flavor"));
		Assert.assertTrue(outputString.contains("Google"));
	}
}
