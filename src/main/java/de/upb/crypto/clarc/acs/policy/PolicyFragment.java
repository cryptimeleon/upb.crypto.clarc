package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import org.apache.commons.lang3.Validate;

public class PolicyFragment {
    final PolicyBuildingContext context;

    PolicyFragment(PolicyBuildingContext context) {
        this.context = context;
    }

    /**
     * Sets the scope of the following attributes to an issuer
     *
     * @param identity The {@link CredentialIssuerPublicIdentity} of an issuer
     * @return -
     */
    public IssuerScopedFragment forIssuer(CredentialIssuerPublicIdentity identity) {
        Validate.notNull(identity, "identity must not be null");
        return new IssuerScopedFragment(context, identity);
    }
}
