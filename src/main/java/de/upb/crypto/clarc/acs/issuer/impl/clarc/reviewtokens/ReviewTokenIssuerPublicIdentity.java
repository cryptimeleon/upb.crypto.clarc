package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerPublicIdentity;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

/**
 * Similar to the {@link CredentialIssuerPublicIdentity}, this is the public identity of the
 * {@link ReviewTokenIssuer}.
 */
public class ReviewTokenIssuerPublicIdentity extends IssuerPublicIdentity
        implements de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewTokenIssuerPublicIdentity {

    public ReviewTokenIssuerPublicIdentity(PSExtendedVerificationKey verificationKey) {
        this.verificationKey = verificationKey.getRepresentation();
    }

    public ReviewTokenIssuerPublicIdentity(Representation representation) {
        verificationKey = representation.obj().get("verificationKey");
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation representation = new ObjectRepresentation();
        representation.put("verificationKey", verificationKey);
        return representation;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ReviewTokenIssuerPublicIdentity that = (ReviewTokenIssuerPublicIdentity) o;
        return Objects.equals(verificationKey, that.verificationKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(verificationKey);
    }

}
