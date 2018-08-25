package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.List;
import java.util.Objects;

/**
 * Clarc implementation of an {@link Issuer}'s {@link de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity}. In this case, the issuer issues
 * credentials and therefore has an {@link AttributeSpace} together with its {@link VerificationKey}.
 */
public class CredentialIssuerPublicIdentity extends IssuerPublicIdentity
        implements de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity {

    @Represented
    private AttributeSpace attributeSpace;

    public CredentialIssuerPublicIdentity(Representation issuerPublicKey,
                                          List<AttributeDefinition> attributeDefinitions) {
        this.attributeSpace = new AttributeSpace(attributeDefinitions, issuerPublicKey);
        this.verificationKey = issuerPublicKey;
    }

    public CredentialIssuerPublicIdentity(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        this.verificationKey = attributeSpace.getIssuerPublicKey();
    }

    @Override
    public AttributeSpace getAttributeSpace() {
        return attributeSpace;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialIssuerPublicIdentity that = (CredentialIssuerPublicIdentity) o;
        return Objects.equals(attributeSpace, that.attributeSpace) &&
                Objects.equals(verificationKey, that.verificationKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(attributeSpace, verificationKey);
    }
}
