package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.interfaces.structures.GroupElement;

/**
 * Simulator for the SetMembershipProofProtocol
 * It simply chooses a W uniformly at random from Zp* and the use the simulator for the inner protocol
 */
public class SetMembershipProtocolSimulator extends SpecialHonestVerifierSimulator {

    public SetMembershipProtocolSimulator(SetMembershipProofProtocol setMembershipProofProtocol) {
        super(setMembershipProofProtocol);
    }

    @Override
    public Transcript simulate(Challenge challenge) {
        SetMembershipProofProtocol protocol = (SetMembershipProofProtocol) this.protocolInstance;
        SetMembershipPublicParameters setPP = (SetMembershipPublicParameters) protocol.getPublicParameters();
        GroupElement w =
                setPP.getNguyenAccumulatorPublicParameters().getG().getStructure().getUniformlyRandomNonNeutral();

        protocol = protocol.updateW(w);

        Transcript transcriptInnerProtocol = protocol.getInnerProtocol().getSimulator().simulate(challenge);
        Announcement[] announcement =
                new Announcement[]{new SetMembershipAnnouncement(transcriptInnerProtocol.getAnnouncements(), w)};
        return new SigmaProtocolTranscript(announcement, challenge, transcriptInnerProtocol.getResponses(), protocol);
    }
}
