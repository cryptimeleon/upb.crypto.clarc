package de.upb.crypto.clarc.acs.user.credentials;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.user.IssueanceReceiver;
import de.upb.crypto.clarc.acs.user.IssuingContext;

public abstract class CredentialIssuanceReceiver<IssuableType extends Issuable,
        IssuedObject extends SignatureCredential> extends IssueanceReceiver<IssuableType, IssuedObject> {

    protected CredentialIssuanceReceiver(IssuableType issuable, IssuingContext issuanceData) {
        super(issuable, issuanceData);
    }
}
