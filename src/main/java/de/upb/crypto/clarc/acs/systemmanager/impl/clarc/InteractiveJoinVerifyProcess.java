package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.JoinVerifyProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.acs.verifier.credentials.InteractiveVerificationProcess;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.util.List;

public class InteractiveJoinVerifyProcess extends InteractiveVerificationProcess {

    private final PublicParameters pp;
    private final GroupElement tau;
    private SystemManagerKeyPair clarcSystemManagerKeyPair;
    private List<RegistrationEntry> registry;
    private UserPublicKey userPublicKey;

    private JoinResponse response;

    InteractiveJoinVerifyProcess(PublicParameters pp, UserPublicKey userPublicKey,
                                 SystemManagerKeyPair clarcSystemManagerKeyPair, Announcement[] announcements,
                                 List<RegistrationEntry> registry,
                                 RegistrationInformation registrationInformation) {
        super(generateProtocol(pp, userPublicKey, clarcSystemManagerKeyPair), announcements);
        this.pp = pp;
        this.userPublicKey = userPublicKey;
        this.clarcSystemManagerKeyPair = clarcSystemManagerKeyPair;
        this.registry = registry;
        tau = pp.getBilinearMap().getG2().getElement(registrationInformation.getTau());
    }

    private static InteractiveThreeWayAoK generateProtocol(PublicParameters pp, UserPublicKey userPublicKey,
                                                           SystemManagerKeyPair clarcSystemManagerKeyPair) {
        JoinVerifyProtocolFactory factory = new JoinVerifyProtocolFactory(
                pp,
                userPublicKey,
                clarcSystemManagerKeyPair.getPublicIdentity().getOpk()
        );
        CommitmentScheme commitmentScheme =
                PublicParametersFactory.getMultiMessageCommitmentScheme(pp);
        return new DamgardTechnique(factory.getProtocol(), commitmentScheme);
    }

    @Override
    public boolean verify(Response[] responses) {
        if (response != null) {
            throw new IllegalStateException("verify must only be called once");
        }
        if (!super.verify(responses) || !checkTau()) {
            return false;
        }

        response = new JoinResponse(
                CreateSignatureHelper.computeSignature(
                        registry, userPublicKey, pp,
                        clarcSystemManagerKeyPair, tau.getRepresentation()
                )
        );
        return true;
    }

    private boolean checkTau() {
        GroupElement upk = pp.getBilinearMap().getG1().getElement(userPublicKey.getUpk());
        BilinearMap map = pp.getBilinearMap();
        final PSExtendedVerificationKey verificationKey = clarcSystemManagerKeyPair.getPublicIdentity().getOpk();
        GroupElement upk_Y = map.apply(upk, verificationKey.getGroup2ElementsTildeYi()[0]);
        GroupElement g_tau = map.apply(verificationKey.getGroup1ElementG(), tau);
        return upk_Y.equals(g_tau);
    }

    public JoinResponse getResponse() {
        return response;
    }
}
