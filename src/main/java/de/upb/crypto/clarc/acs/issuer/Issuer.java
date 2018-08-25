package de.upb.crypto.clarc.acs.issuer;

import de.upb.crypto.clarc.acs.pseudonym.Pseudonym;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.acs.user.credentials.Credential;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface Issuer<IssuableType extends Issuable, IssuedObject extends StandaloneRepresentable>
        extends StandaloneRepresentable {
    InteractiveIssueIssuableProcess initInteractiveIssueProcess(CommitmentValue commitment,
                                                                Pseudonym pseudonym,
                                                                IssuableType issuable,
                                                                Announcement[] announcements);

    /**
     * Creates an {@link IssueResponse} based on a {@link NonInteractiveIssuableRequest} object
     *
     * @param nonInteractiveIssuableRequest The {@link NonInteractiveIssuableRequest} object which contains the
     *                                      necessary info and proofs of the users secret values
     * @return An {@link IssueResponse} which contains the information necessary to construct the
     * requested {@link Credential}
     */
    IssueResponse<IssuedObject> issueNonInteractively(
            NonInteractiveIssuableRequest<IssuableType> nonInteractiveIssuableRequest);

    /**
     * Get the {@link Issuer}'s {@link IssuerPublicIdentity} containing its public key
     *
     * @return this {@link Issuer}'s {@link IssuerPublicIdentity}
     */
    IssuerPublicIdentity getPublicIdentity();
}
