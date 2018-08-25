package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.interfaces.structures.GroupElement;

public class InequalityProtocolSimulator extends SpecialHonestVerifierSimulator {


    public InequalityProtocolSimulator(InequalityProofProtocol inequalityProofProtocol) {
        super(inequalityProofProtocol);
    }

    @Override
    public Transcript simulate(Challenge challege) {
        InequalityProofProtocol protocol = (InequalityProofProtocol) this.protocolInstance;
        InequalityPublicParameters ipp = (InequalityPublicParameters) protocol.getPublicParameters();
        GroupElement w = ipp.getG2().getStructure().getUniformlyRandomNonNeutral();

        protocol = protocol.updateW(w);

        Transcript transcriptInnerProtocol = protocol.getInnerProtocol().getSimulator().simulate(challege);
        return new SigmaProtocolTranscript(new Announcement[]{
                new InequalityAnnouncement(transcriptInnerProtocol.getAnnouncements(), w)}
                , challege, transcriptInnerProtocol.getResponses(), protocol);
    }
}
