package com.uid2.attestation.gcp;

import com.uid2.enclave.AttestationException;
import com.uid2.enclave.IAttestationProvider;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

public class VmidAttestationProvider implements IAttestationProvider {
	// the url endpoint to send instance document request to
	private String metadataEndpoint = "http://metadata/computeMetadata/v1/instance/service-accounts/default/identity";

	@Override
	public byte[] getAttestationRequest(byte[] publicKey, byte[] userData) throws AttestationException {
		// encode publicKey into base64 string and pass as audience
		String audience = Base64.getEncoder().encodeToString(publicKey);

		String instanceDocument = null;
		try {
			instanceDocument = obtainInstanceDocument(audience);
		} catch (IOException e) {
			throw new AttestationException(e);
		}
		return instanceDocument.getBytes(StandardCharsets.US_ASCII);
	}

	public void setMetadataEndpoint(String newEndpoint) {
		this.metadataEndpoint = newEndpoint;
	}

	private String obtainInstanceDocument(String audience) throws IOException {
		// curl -H "Metadata-Flavor: Google" \
		//   'http://metadata/computeMetadata/v1/instance/service-accounts/default/identity?audience=$AUDIENCE&format=full'

		final String query = String.format("?audience=%s&format=full",
			URLEncoder.encode(audience, StandardCharsets.US_ASCII.toString()));

		final URL url = new URL(this.metadataEndpoint + query);
		final URLConnection conn = url.openConnection();
		conn.setRequestProperty("Metadata-Flavor", "Google");

		return readToEnd(conn.getInputStream());
	}

	private static String readToEnd(InputStream stream) throws IOException {
		final InputStreamReader reader = new InputStreamReader(stream);
		final char[] buff = new char[1024];
		final StringBuilder sb = new StringBuilder();
		for (int count; (count = reader.read(buff, 0, buff.length)) > 0;) {
			sb.append(buff, 0, count);
		}
		return sb.toString();
	}
}
