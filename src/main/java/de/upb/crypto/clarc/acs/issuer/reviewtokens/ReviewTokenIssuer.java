package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.pseudonym.Pseudonym;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface ReviewTokenIssuer<IssuableType extends Issuable> extends StandaloneRepresentable {

    InteractiveRequestReviewTokenProcess createInteractiveIssueReviewTokenProcess(CommitmentValue commitment,
                                                                                  Pseudonym pseudonym,
                                                                                  IssuableType issuable,
                                                                                  Announcement[] announcements);

    /**
     * Creates a {@link ReviewTokenResponse} based on a {@link NonInteractiveIssuableRequest} object
     *
     * @param nonInteractiveIssuableRequest The {@link NonInteractiveIssuableRequest} object which contains the
     *                                      necessary info and proofs of the users secret values
     * @return A {@link ReviewTokenResponse} which contains the information necessary to construct the
     * requested {@link ReviewToken}
     */
    ReviewTokenResponse issueReviewTokenNonInteractively(
            NonInteractiveIssuableRequest<IssuableType> nonInteractiveIssuableRequest);

    /**
     * Get the {@link ReviewTokenIssuer}'s {@link ReviewTokenIssuerPublicIdentity} containing its public key.
     *
     * @return this {@link ReviewTokenIssuer}'s {@link ReviewTokenIssuerPublicIdentity}
     */
    ReviewTokenIssuerPublicIdentity getPublicIdentity();
}
