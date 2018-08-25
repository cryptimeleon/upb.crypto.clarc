package de.upb.crypto.clarc.acs.verifier.credentials;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;

/**
 * Provides a simple to use wrapper for managing the process of checking whether a user can fulfill a protocol with a
 * given policy
 */
public class InteractiveVerificationProcess {
    private final Challenge challenge;
    private final Announcement[] announcements;
    private final InteractiveThreeWayAoK protocol;

    public InteractiveVerificationProcess(InteractiveThreeWayAoK protocol, Announcement[] announcements) {
        this.protocol = protocol;
        challenge = protocol.chooseChallenge();
        this.announcements = announcements;
    }

    /**
     * Getter for the challenge for the current verification process
     *
     * @return The challenge for the user
     */
    public Challenge getChallenge() {
        return challenge;
    }

    /**
     * Verifies whether the announcement, challenge and response prove that the user fulfills the policy of the protocol
     *
     * @param responses The response of the user to the previously generated challenge
     * @return true if the user fulfills the policy of the protocol, false otherwise
     */
    public boolean verify(Response[] responses) {
        return protocol.verify(announcements, challenge, responses);
    }
}
