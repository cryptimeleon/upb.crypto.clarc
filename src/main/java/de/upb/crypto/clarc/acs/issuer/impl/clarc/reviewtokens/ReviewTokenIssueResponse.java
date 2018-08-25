package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewTokenResponse;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.math.serialization.Representation;

/**
 * This is a possible response from the {@link Issuer} during the {@link InteractiveRequestReviewTokenProcess}
 * or {@link NonInteractiveIssuableRequest} for {@link de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken}. It uses the StandaloneRepresentable
 * variant of the review token.
 */
public class ReviewTokenIssueResponse extends ReviewTokenResponse<RepresentableReviewToken> {

    public ReviewTokenIssueResponse(RepresentableReviewToken clarcRepresentableReviewToken) {
        super(clarcRepresentableReviewToken);
    }

    public ReviewTokenIssueResponse(Representation representation) {
        super(representation);
    }
}
