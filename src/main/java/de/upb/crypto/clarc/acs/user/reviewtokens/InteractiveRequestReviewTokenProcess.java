package de.upb.crypto.clarc.acs.user.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.user.InteractiveIssuingContext;
import de.upb.crypto.clarc.acs.user.InteractiveRequestIssuableProcess;
import de.upb.crypto.clarc.acs.user.User;

public abstract class InteractiveRequestReviewTokenProcess<IssuableType extends Issuable,
        IssuedObject extends RepresentableReviewToken>
        extends InteractiveRequestIssuableProcess<IssuableType, IssuedObject> {
    /**
     * Initializes the process of requesting a credential for the user with all needed parameters.
     *
     * @param data     {@link InteractiveIssuingContext} containing all information needed from the {@link User}
     * @param issuable The item the user wants to be signed
     */
    public InteractiveRequestReviewTokenProcess(InteractiveIssuingContext data, IssuableType issuable,
                                                ReviewTokenIssuanceReceiver<IssuableType, IssuedObject> receiver) {
        super(data, null, issuable, receiver);
    }
}
