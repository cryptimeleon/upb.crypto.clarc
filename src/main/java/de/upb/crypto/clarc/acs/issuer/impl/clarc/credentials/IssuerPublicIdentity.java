package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.math.serialization.Representation;

public abstract class IssuerPublicIdentity implements de.upb.crypto.clarc.acs.issuer.IssuerPublicIdentity {
    protected Representation verificationKey;

    @Override
    public Representation getIssuerPublicKey() {
        return verificationKey;
    }
}
