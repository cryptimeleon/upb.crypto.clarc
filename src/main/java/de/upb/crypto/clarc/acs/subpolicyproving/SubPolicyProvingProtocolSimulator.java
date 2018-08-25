package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.protocols.simulator.SigmaProtocolTranscript;
import de.upb.crypto.clarc.protocols.simulator.SpecialHonestVerifierSimulator;
import de.upb.crypto.clarc.protocols.simulator.Transcript;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.util.ArrayList;
import java.util.List;

public class SubPolicyProvingProtocolSimulator extends SpecialHonestVerifierSimulator {
    public SubPolicyProvingProtocolSimulator(SubPolicyProvingProtocol proveCredAndPredicateProtocol) {
        super(proveCredAndPredicateProtocol);
    }

    @Override
    public Transcript simulate(Challenge challege) {
        SubPolicyProvingProtocol subPolicyProvingProtocol = (SubPolicyProvingProtocol) protocolInstance;

        SubPolicyProvingProtocol proveCredAndPredicateProtocol =
                (SubPolicyProvingProtocol) this.protocolInstance;
        SubPolicyProvingProtocolPublicParameters subPolPP =
                (SubPolicyProvingProtocolPublicParameters) subPolicyProvingProtocol.getPublicParameters();


        // Choose commitments randomly. Number is extracted from attribute space.
        Group group = subPolPP.getCommitmentScheme().getPp().getGroup();
        List<PedersenCommitmentValue> randomCommitments = new ArrayList<>();
        for (int i = 0; i < subPolPP.getAttributeSpace().getDefinitions().size(); i++) {
            randomCommitments.add(new PedersenCommitmentValue(group.getUniformlyRandomElement()));
        }
        subPolPP.setCommitmentsOnAttributes(randomCommitments);
        subPolicyProvingProtocol.setPublicParameters(subPolPP);

        // Choose randomized signature
        PSPublicParameters pspp = subPolPP.getPsSignatureScheme().getPp();
        GroupElement sigma1 = pspp.getBilinearMap().getG1().getUniformlyRandomNonNeutral();
        GroupElement sigma2 = pspp.getBilinearMap().getG1().getUniformlyRandomElement();

        PSSignature signature = new PSSignature(sigma1, sigma2);
        subPolPP.setRandomizedSignature(signature);

        // Since the randomized signature is needed to create the underlying protocols, the P1 instance need to be reset
        SubPolicyProvingProtocol fullInstance = new SubPolicyProvingProtocol(new EmptyWitness(), subPolPP);
        SpecialHonestVerifierSimulator signSimulator = fullInstance.getProtocolForSignature().getSimulator();
        Transcript signTranscript = signSimulator.simulate(challege);

        SpecialHonestVerifierSimulator popkSimulator = fullInstance.getPredicateProvingProtocol().getSimulator();
        Transcript popkTranscript = popkSimulator.simulate(challege);

        SubPolicyProvingProtocolAnnouncement subPolicyProvingProtocolAnnouncement =
                new SubPolicyProvingProtocolAnnouncement(signature, randomCommitments, subPolPP.getDisclosedElements(),
                        popkTranscript.getAnnouncements(), signTranscript.getAnnouncements());
        SubPolicyProvingProtocolResponse subPolicyProvingProtocolResponse =
                new SubPolicyProvingProtocolResponse(signTranscript.getResponses(), popkTranscript.getResponses());
        return new SigmaProtocolTranscript(new Announcement[]{subPolicyProvingProtocolAnnouncement}, challege, new
                Response[]{subPolicyProvingProtocolResponse}, fullInstance);
    }
}
