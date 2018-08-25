package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.math.serialization.Representation;

/**
 * This is a possible response from the {@link Issuer} during the {@link InteractiveRequestReviewTokenProcess}
 * or {@link NonInteractiveIssuableRequest} for {@link RepresentableReviewToken}. It uses the StandaloneRepresentable
 * variant of the review token.
 */
public abstract class ReviewTokenResponse<IssuedObject extends RepresentableReviewToken>
        extends IssueResponse<IssuedObject> {
    public ReviewTokenResponse(IssuedObject issuedObject) {
        super(issuedObject);
    }

    public ReviewTokenResponse(Representation representation) {
        super(representation);
    }
}
