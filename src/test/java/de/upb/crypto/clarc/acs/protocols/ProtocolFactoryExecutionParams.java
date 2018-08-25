package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.craco.interfaces.policy.Policy;

public class ProtocolFactoryExecutionParams {
    public final CredentialIssuer[] issuers;
    public final PSCredential[] fulfillingCredentials;
    public final SelectiveDisclosure[] disclosures;
    public final Policy policy;

    ProtocolFactoryExecutionParams(CredentialIssuer[] issuers,
                                   PSCredential[] fulfillingCredentials,
                                   SelectiveDisclosure[] disclosures,
                                   Policy policy) {
        this.issuers = issuers;
        this.fulfillingCredentials = fulfillingCredentials;
        this.disclosures = disclosures;
        this.policy = policy;
    }
}
