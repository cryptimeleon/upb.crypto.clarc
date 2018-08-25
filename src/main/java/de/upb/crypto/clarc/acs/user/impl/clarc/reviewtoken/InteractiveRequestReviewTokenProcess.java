package de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.user.impl.clarc.IssuingContext;

public class InteractiveRequestReviewTokenProcess extends
        de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess<HashOfItem, RepresentableReviewToken> {

    public InteractiveRequestReviewTokenProcess(IssuingContext data,
                                                HashOfItem issuable) {
        super(data, issuable, new NonInteractiveReviewTokenReceiver(issuable, data));
    }

}
