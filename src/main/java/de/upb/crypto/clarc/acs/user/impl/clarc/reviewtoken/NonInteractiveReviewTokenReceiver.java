package de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken;

import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.user.impl.clarc.IssuingContext;
import de.upb.crypto.clarc.acs.user.reviewtokens.ReviewTokenIssuanceReceiver;

public class NonInteractiveReviewTokenReceiver extends
        ReviewTokenIssuanceReceiver<HashOfItem, RepresentableReviewToken> {

    public NonInteractiveReviewTokenReceiver(HashOfItem issuable,
                                             IssuingContext issuanceData) {
        super(issuable, issuanceData);
    }

    @Override
    public RepresentableReviewToken receive(IssueResponse<RepresentableReviewToken> response) {
        IssuingContext clarcIssuanceData = (IssuingContext) issuanceData;
        return ReceiveReviewTokenHelper.unblindReviewToken(
                clarcIssuanceData.getPp(),
                response,
                clarcIssuanceData.getUskCommitPair().getOpenValue(),
                issuable,
                clarcIssuanceData.getUsk(),
                clarcIssuanceData.getIssuerPublicIdentity());
    }
}
