package de.upb.crypto.clarc.acs.user.credentials;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.user.IssueanceReceiver;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.NonInteractiveResponseHandler;

public abstract class CredentialNonInteractiveResponseHandler<IssuableType extends Issuable,
        IssuedObject extends SignatureCredential> extends NonInteractiveResponseHandler<IssuableType, IssuedObject> {

    protected CredentialNonInteractiveResponseHandler(
            NonInteractiveIssuableRequest<IssuableType> request,
            IssueanceReceiver<IssuableType, IssuedObject> receiver) {
        super(request, receiver);
    }
}
