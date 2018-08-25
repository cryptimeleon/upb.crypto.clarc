package de.upb.crypto.clarc.acs.user.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.user.IssueanceReceiver;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.NonInteractiveResponseHandler;

public abstract class ReviewTokeIssueanceState<IssuableType extends Issuable,
        IssuedObject extends RepresentableReviewToken>
        extends NonInteractiveResponseHandler<IssuableType, IssuedObject> {

    public ReviewTokeIssueanceState(
            NonInteractiveIssuableRequest<IssuableType> request,
            IssueanceReceiver<IssuableType, IssuedObject> receiver) {
        super(request, receiver);
    }
}
