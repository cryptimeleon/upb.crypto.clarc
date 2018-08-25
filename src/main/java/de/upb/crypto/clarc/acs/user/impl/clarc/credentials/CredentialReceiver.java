package de.upb.crypto.clarc.acs.user.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.user.credentials.CredentialIssuanceReceiver;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.IssuingContext;

public class CredentialReceiver extends CredentialIssuanceReceiver<Attributes, PSCredential> {


    public CredentialReceiver(Attributes issuable, IssuingContext issuanceData) {
        super(issuable, issuanceData);
    }

    @Override
    public PSCredential receive(IssueResponse<PSCredential> response) {
        IssuingContext clarcIssuanceData = (IssuingContext) issuanceData;
        return ReceiveCredentialHelper.unblindCredential(
                clarcIssuanceData.getPp(),
                response,
                clarcIssuanceData.getUskCommitPair().getOpenValue(),
                issuable,
                clarcIssuanceData.getUsk(),
                (CredentialIssuerPublicIdentity) clarcIssuanceData.getIssuerPublicIdentity());
    }
}
