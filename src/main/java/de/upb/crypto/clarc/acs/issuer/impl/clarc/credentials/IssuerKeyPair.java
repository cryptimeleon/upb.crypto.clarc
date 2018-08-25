package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

/**
 * Specific implementation of the {@link de.upb.crypto.clarc.acs.issuer.credentials.IssuerKeyPair}.
 */
public class IssuerKeyPair extends de.upb.crypto.clarc.acs.issuer.credentials.IssuerKeyPair {

    private PSSigningKey signingKey;
    private PSExtendedVerificationKey verificationKey;

    public IssuerKeyPair(PSSigningKey signingKey, PSExtendedVerificationKey verificationKey) {
        this.signingKey = signingKey;
        this.verificationKey = verificationKey;
    }

    public IssuerKeyPair(Representation representation, Zp zp, Group g1, Group g2) {
        signingKey = new PSSigningKey(representation.obj().get("signingKey"), zp);
        verificationKey = new PSExtendedVerificationKey(g1, g2, representation.obj().get("verificationKey"));

    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("signingKey", signingKey.getRepresentation());
        representation.put("verificationKey", verificationKey.getRepresentation());
        return representation;
    }

    public PSSigningKey getSigningKey() {
        return signingKey;
    }

    public PSExtendedVerificationKey getVerificationKey() {
        return verificationKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        IssuerKeyPair that = (IssuerKeyPair) o;
        return Objects.equals(signingKey, that.signingKey) &&
                Objects.equals(verificationKey, that.verificationKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signingKey, verificationKey);
    }
}
