package de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.user.reviewtokens.ReviewTokeIssueanceState;

public class ReviewTokenNonInteractiveResponseHandler
        extends ReviewTokeIssueanceState<HashOfItem, RepresentableReviewToken> {
    public ReviewTokenNonInteractiveResponseHandler(
            NonInteractiveReviewTokenRequest request,
            NonInteractiveReviewTokenReceiver receiver) {
        super(request, receiver);
    }
}
