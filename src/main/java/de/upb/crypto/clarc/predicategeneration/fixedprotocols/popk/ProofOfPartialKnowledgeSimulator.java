package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.clarc.predicategeneration.policies.SigmaProtocolPolicyFact;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrChallenge;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class ProofOfPartialKnowledgeSimulator extends SpecialHonestVerifierSimulator {
    public ProofOfPartialKnowledgeSimulator(ProofOfPartialKnowledgeProtocol poPKProtocol) {
        super(poPKProtocol);
    }


    @Override
    public Transcript simulate(Challenge challege) {
        if (!(challege instanceof GeneralizedSchnorrChallenge)) {
            throw new IllegalArgumentException("The given challenge cannot be used in this protocol");
        }
        ProofOfPartialKnowledgeProtocol popk = (ProofOfPartialKnowledgeProtocol) super.protocolInstance;

        // Firstly the challenge need to be shared among the protocols using the linear secret sharing
        Map<Integer, Zp.ZpElement> sharedChallenge =
                popk.getSecretSharing().getShares(((GeneralizedSchnorrChallenge) challege).getChallenge());

        // Compute transcripts using shared challenges
        Map<Integer, Transcript> simulatedProtocolExecutions = new LinkedHashMap<>(sharedChallenge.size());
        List<SigmaProtocol> usedProtocols = popk.getSecretSharing().getShareReceiverMap().values().stream()
                .map(policy -> ((SigmaProtocolPolicyFact) policy).getProtocol())
                .collect(Collectors.toList());
        // Per contract of linear secret sharing all shares are indexed from 1,..,n.
        // Therefore we need to "shift" the position by 1
        for (int i = 1; i <= popk.getSecretSharing().getShareReceiverMap().size(); i++) {
            Challenge c = new GeneralizedSchnorrChallenge(sharedChallenge.get(i));
            simulatedProtocolExecutions.put(i, usedProtocols.get(i - 1).getSimulator().simulate(c));
        }
        ProofOfPartialKnowledgeAnnouncement[] announcements =
                new ProofOfPartialKnowledgeAnnouncement[simulatedProtocolExecutions.size()];
        ProofOfPartialKnowledgeResponse[] responses =
                new ProofOfPartialKnowledgeResponse[simulatedProtocolExecutions.size()];
        for (int i = 0; i < simulatedProtocolExecutions.size(); i++) {
            // Since the mapping of the protocols is done using the position in secret sharing (starting at 1), the +1
            // is needed
            Transcript transcriptFori = simulatedProtocolExecutions.get(i + 1);
            announcements[i] = new ProofOfPartialKnowledgeAnnouncement(i + 1, transcriptFori.getAnnouncements());
            responses[i] = new ProofOfPartialKnowledgeResponse(i + 1, transcriptFori.getResponses(),
                    sharedChallenge.get(i + 1));
        }
        return new SigmaProtocolTranscript(announcements, challege, responses, popk);
    }
}
