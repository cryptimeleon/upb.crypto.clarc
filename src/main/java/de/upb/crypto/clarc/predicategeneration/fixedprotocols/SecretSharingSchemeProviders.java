package de.upb.crypto.clarc.predicategeneration.fixedprotocols;

import de.upb.crypto.craco.interfaces.abe.LinearSecretSharing;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ShamirSecretSharing;
import de.upb.crypto.craco.secretsharing.ShamirSecretSharingSchemeProvider;

/**
 * Collection of providers for {@link LinearSecretSharing} instances used for proofs of partial knowledge
 * during protocol execution.
 */
public class SecretSharingSchemeProviders {
    /**
     * Provider which creates instances of {@link ShamirSecretSharing}
     */
    public static SecretSharingSchemeProvider SHAMIR = new ShamirSecretSharingSchemeProvider();
}
