package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;

/**
 * Simulator for the {@link ZeroToUPowLRangeProofProtocol}
 * It simply chooses W_jHats uniformly at random from Zp* and the use the simulator for the inner protocol
 */
public class ZeroToUPowLRangeProofProtocolSimulator extends SpecialHonestVerifierSimulator {

    public ZeroToUPowLRangeProofProtocolSimulator(ZeroToUPowLRangeProofProtocol rangeProofProofProtocol) {
        super(rangeProofProofProtocol);
    }

    @Override
    public Transcript simulate(Challenge challenge) {
        ZeroToUPowLRangeProofProtocol protocol = (ZeroToUPowLRangeProofProtocol) this.protocolInstance;
        ZeroToUPowLRangeProofPublicParameters rangePP = protocol.getPublicParameters();
        GroupElement[] randomizedAccWitnesses = new GroupElement[rangePP.getExponent()];
        Group group = rangePP.getNguyenAccumulatorPublicParameters().getG().getStructure();
        for (int i = 0; i < rangePP.getExponent(); i++) {
            randomizedAccWitnesses[i] = group.getUniformlyRandomNonNeutral();
        }

        Transcript transcriptInnerProtocol = protocol.createInternalVerifierProtocol(randomizedAccWitnesses).getSimulator().simulate(challenge);

        Announcement[] announcement = new Announcement[]{
                new ZeroToUPowLRangeProofAnnouncement(transcriptInnerProtocol.getAnnouncements(), randomizedAccWitnesses)};
        Response[] responses =
                new Response[]{new ZeroToUPowLRangeProofResponse(transcriptInnerProtocol.getResponses())};
        return new SigmaProtocolTranscript(announcement, challenge, responses, protocol);
    }
}