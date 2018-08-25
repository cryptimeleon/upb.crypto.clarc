package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.protocols.ProtocolParameters;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.sig.ps.PSSignature;

/**
 * Provides a simple to use wrapper for managing the process of proving credentials to an verifier
 */
public class InteractiveProvingProcess {
    private final InteractiveThreeWayAoK protocol;
    private final Announcement[] announcements;
    private final ProtocolParameters protocolParameters;
    private PSSignature masterCredential = null;

    public InteractiveProvingProcess(InteractiveThreeWayAoK protocol, ProtocolParameters protocolParameters, PSSignature masterCredential) {
        this(protocol, protocolParameters);
        this.masterCredential = masterCredential;
    }

    public InteractiveProvingProcess(InteractiveThreeWayAoK protocol, ProtocolParameters protocolParameters) {
        this.protocol = protocol;
        announcements = protocol.generateAnnouncements();
        this.protocolParameters = protocolParameters;
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }

    public ProtocolParameters getProtocolParameters() {
        return protocolParameters;
    }

    public PSSignature getMasterCredential() {
        return masterCredential;
    }

    /**
     * Generates the responses after a challenge of a verifier was received
     *
     * @param challenge The challenge which the verifier chose based on the previously generated announcement
     * @return Array of the responses which allows the verifier to check whether the policy of the protocol was
     * satisfied
     */
    public Response[] getResponses(Challenge challenge) {
        return protocol.generateResponses(challenge);
    }
}
