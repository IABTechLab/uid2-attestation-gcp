package com.uid2.attestation.gcp;

import com.google.api.gax.retrying.RetrySettings;
import com.google.cloud.secretmanager.v1.*;
import com.google.common.base.Strings;
import com.uid2.enclave.IOperatorKeyRetriever;
import io.grpc.LoadBalancerRegistry;
import io.grpc.internal.PickFirstLoadBalancerProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.threeten.bp.Duration;

import java.io.IOException;

public class GcpOperatorKeyRetriever implements IOperatorKeyRetriever {
    private static final Logger LOGGER = LoggerFactory.getLogger(GcpOperatorKeyRetriever.class);
    private final SecretVersionName secretVersionName;

    /**
     * Retrieve secret value from GCP SecretManager
     * @param secretVersionName in "projects/{project}/secrets/{secret}/versions/{secret_version}" format
     */
    public GcpOperatorKeyRetriever(String secretVersionName){
        if (Strings.isNullOrEmpty(secretVersionName)) {
            throw new IllegalArgumentException("secretVersionName is null or empty");
        }
        // Will throw IllegalArgument Exception for invalid format
        this.secretVersionName = SecretVersionName.parse(secretVersionName);

        LoadBalancerRegistry.getDefaultRegistry().register(new PickFirstLoadBalancerProvider());
    }

    @Override
    public String retrieve() {
        var retrySetting = RetrySettings.newBuilder()
                .setInitialRetryDelay(Duration.ofSeconds(3))
                .setMaxRetryDelay(Duration.ofSeconds(3))
                .setMaxAttempts(3)
                .build();
        var settingsBuilder =SecretManagerServiceSettings.newBuilder();
        settingsBuilder.accessSecretVersionSettings().setRetrySettings(retrySetting);

        try(var client = SecretManagerServiceClient.create(settingsBuilder.build())) {
            LOGGER.info(String.format("Load OperatorKey secret (%s).", this.secretVersionName));

            var response = client.accessSecretVersion(this.secretVersionName);
            String payload = response.getPayload().getData().toStringUtf8();

            LOGGER.info("OperatorKey secret is loaded.");
            return payload;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
