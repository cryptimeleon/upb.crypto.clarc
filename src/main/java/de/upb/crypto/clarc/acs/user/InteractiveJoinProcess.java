package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.JoinProtocolFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.RegistrationInformation;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserKeyPair;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;

public class InteractiveJoinProcess {

    private de.upb.crypto.clarc.acs.systemmanager.RegistrationInformation registrationInformation;
    private InteractiveThreeWayAoK protocol;
    private Announcement[] announcements;
    private UserKeyPair clarcUserKeyPair;

    public InteractiveJoinProcess(PublicParameters pp, UserKeyPair clarcUserKeyPair,
                                  SystemManagerPublicIdentity systemManagerPublicIdentity) {
        this.clarcUserKeyPair = clarcUserKeyPair;
        final PSExtendedVerificationKey systemManagerVerificationKey = systemManagerPublicIdentity.getOpk();
        this.protocol = generateProtocol(pp, clarcUserKeyPair, systemManagerVerificationKey);
        this.announcements = protocol.generateAnnouncements();

        GroupElement tau = systemManagerVerificationKey.getGroup2ElementsTildeYi()[0]
                .pow(clarcUserKeyPair.getUserSecret().getUsk());
        this.registrationInformation = new RegistrationInformation(tau);
    }

    private static InteractiveThreeWayAoK generateProtocol(PublicParameters pp, UserKeyPair userKeyPair,
                                                           PSExtendedVerificationKey systemManagerPublicKey) {
        JoinProtocolFactory factory = new JoinProtocolFactory(pp, userKeyPair, systemManagerPublicKey);
        CommitmentScheme commitmentScheme =
                PublicParametersFactory.getMultiMessageCommitmentScheme(pp);
        return new DamgardTechnique(factory.getProtocol(), commitmentScheme);
    }

    public de.upb.crypto.clarc.acs.systemmanager.RegistrationInformation getRegistrationInformation() {
        return registrationInformation;
    }

    public Announcement[] getAnnouncements() {
        return announcements;
    }

    public Response[] getResponses(Challenge challenge) {
        return protocol.generateResponses(challenge);
    }

    private boolean checkJoinSignature(PublicParameters pp, PSSignature psSignature,
                                       PSExtendedVerificationKey systemManagerPublicKey) {
        Group g1 = pp.getBilinearMap().getG1();
        GroupElement sigma_1 = psSignature.getGroup1ElementSigma1();
        GroupElement sigma_2 = psSignature.getGroup1ElementSigma2();
        if (sigma_1.equals(g1.getNeutralElement())) {
            return false;
        }
        BilinearMap map = pp.getBilinearMap();
        GroupElement x_tilde = systemManagerPublicKey.getGroup2ElementTildeX();
        GroupElement y_tilde = systemManagerPublicKey.getGroup2ElementsTildeYi()[0];

        GroupElement leftSide = map.apply(sigma_1, x_tilde.op(y_tilde.pow(clarcUserKeyPair.getUserSecret().getUsk())));
        GroupElement rightSide = map.apply(sigma_2, systemManagerPublicKey.getGroup2ElementTildeG());
        return rightSide.equals(leftSide);
    }

}
