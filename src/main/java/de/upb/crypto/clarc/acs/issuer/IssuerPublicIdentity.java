package de.upb.crypto.clarc.acs.issuer;

import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface IssuerPublicIdentity extends StandaloneRepresentable {
    /**
     * @return the {@link Issuer}'s public key
     */
    Representation getIssuerPublicKey();

}
