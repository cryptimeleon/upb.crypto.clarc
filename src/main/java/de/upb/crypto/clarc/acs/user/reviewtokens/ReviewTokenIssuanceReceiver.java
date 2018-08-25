package de.upb.crypto.clarc.acs.user.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.user.IssueanceReceiver;
import de.upb.crypto.clarc.acs.user.IssuingContext;

public abstract class ReviewTokenIssuanceReceiver<IssuableType extends Issuable,
        IssuedObject extends RepresentableReviewToken>
        extends IssueanceReceiver<IssuableType, IssuedObject> {
    protected ReviewTokenIssuanceReceiver(IssuableType issuable, IssuingContext issuanceData) {
        super(issuable, issuanceData);
    }
}
