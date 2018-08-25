package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.math.serialization.Representation;

public class CredentialIssueResponse extends IssueResponse<PSCredential> {
    public CredentialIssueResponse(PSCredential psCredential) {
        super(psCredential);
    }

    public CredentialIssueResponse(Representation representation) {
        super(representation);
    }
}
