package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;

/**
 * Marker interface for auxiliary information to be provided by the {@link User} during an
 * {@link InteractiveRequestIssuableProcess}, which are able to create a {@link InteractiveThreeWayAoK}
 * proving knowledge of these data.
 */
public interface InteractiveIssuingContext extends IssuingContext {
    /**
     * Generates a {@link InteractiveThreeWayAoK} proving knowledge of the auxiliary information to be provided by the
     * {@link User} during a {@link InteractiveRequestIssuableProcess}.
     *
     * @return {@link InteractiveThreeWayAoK} proving knowledge of the {@link User}'s secret data during
     * {@link InteractiveRequestIssuableProcess}
     */
    InteractiveThreeWayAoK generateProtocol();

    /**
     * @return the {@link CommitmentValue} on the {@link UserSecret} used during issuing
     */
    CommitmentValue getUskCommitmentValue();
}
