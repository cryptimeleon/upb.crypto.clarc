package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;

/**
 * Simulator for the {@link ArbitraryRangeProofProtocol}
 * It simply chooses W_jHats uniformly at random from Zp* and the use the simulator for the inner protocol
 */
public class ArbitraryRangeProofProtocolSimulator extends SpecialHonestVerifierSimulator {

    public ArbitraryRangeProofProtocolSimulator(ArbitraryRangeProofProtocol rangeProofProofProtocol) {
        super(rangeProofProofProtocol);
    }

    @Override
    public Transcript simulate(Challenge challenge) {
        ArbitraryRangeProofProtocol protocol = (ArbitraryRangeProofProtocol) this.protocolInstance;

        Transcript transcriptLowerProtocol = protocol.instantiateInnerLowerBoundProtocol().getSimulator().simulate(challenge);
        Transcript transcriptUpperProtocol = protocol.instantiateInnerUpperBoundProtocol().getSimulator().simulate(challenge);

        Announcement[] announcement = new Announcement[]{
                new ArbitraryRangeProofAnnouncement(transcriptLowerProtocol.getAnnouncements(), transcriptUpperProtocol.getAnnouncements())};
        Response[] responses = new Response[]{new ArbitraryRangeProofResponse(transcriptLowerProtocol.getResponses(),
                transcriptUpperProtocol.getResponses())};
        return new SigmaProtocolTranscript(announcement, challenge, responses, protocol);
    }
}