package de.upb.crypto.clarc.acs.issuer.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.issuer.IssuerPublicIdentity;

/**
 * Definition of an {@link Issuer}'s {@link CredentialIssuerPublicIdentity} containing its public key as well as its
 * {@link AttributeSpace}
 */
public interface CredentialIssuerPublicIdentity extends IssuerPublicIdentity {
    /**
     * @return the {@link Issuer}'s {@link AttributeSpace}
     */
    AttributeSpace getAttributeSpace();
}
