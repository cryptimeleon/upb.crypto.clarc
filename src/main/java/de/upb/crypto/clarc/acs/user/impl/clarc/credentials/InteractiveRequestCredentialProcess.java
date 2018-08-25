package de.upb.crypto.clarc.acs.user.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.IssuingContext;

public class InteractiveRequestCredentialProcess
        extends de.upb.crypto.clarc.acs.user.credentials.InteractiveRequestCredentialProcess<Attributes, PSCredential> {

    public InteractiveRequestCredentialProcess(IssuingContext data,
                                               Attributes issuable) {
        super(data, issuable, new CredentialReceiver(issuable, data));
    }
}
