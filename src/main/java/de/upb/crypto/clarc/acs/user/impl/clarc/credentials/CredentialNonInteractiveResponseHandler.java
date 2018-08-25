package de.upb.crypto.clarc.acs.user.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;

public class CredentialNonInteractiveResponseHandler
        extends
        de.upb.crypto.clarc.acs.user.credentials.CredentialNonInteractiveResponseHandler<Attributes, PSCredential> {

    public CredentialNonInteractiveResponseHandler(
            NonInteractiveCredentialRequest request,
            CredentialReceiver receiver) {
        super(request, receiver);
    }
}
