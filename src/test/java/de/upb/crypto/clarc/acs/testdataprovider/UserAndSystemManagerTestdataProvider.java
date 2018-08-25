package de.upb.crypto.clarc.acs.testdataprovider;

import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.RegistrationInformation;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.InteractiveJoinVerifyProcess;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerKeyPair;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerKeyPairFactory;
import de.upb.crypto.clarc.acs.user.InteractiveJoinProcess;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserKeyPair;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Arrays;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Setup and registers a new user
 */
public class UserAndSystemManagerTestdataProvider {

    private final SystemManager systemManager;
    private final RegistrationInformation registrationInformation;

    private final User clarcUser;
    private final Identity clarcIdentity;
    private final UserSecret clarcUserSecret;
    private final SystemManagerKeyPair clarcSystemManagerKeyPair;


    public UserAndSystemManagerTestdataProvider(PublicParameters clarcPublicParameters) {

        this.clarcUser = new User(clarcPublicParameters);

        SystemManagerKeyPairFactory openFactory = new SystemManagerKeyPairFactory();
        clarcSystemManagerKeyPair = openFactory.create(clarcPublicParameters);
        systemManager = new SystemManager(clarcPublicParameters);

        InteractiveJoinProcess joinProcess = clarcUser.initInteractiveJoinProcess(systemManager.getPublicIdentity());
        registrationInformation = joinProcess.getRegistrationInformation();
        InteractiveJoinVerifyProcess verifyProcess =
                systemManager.initInteractiveJoinVerifyProcess(clarcUser.getPublicKey(),
                        joinProcess.getAnnouncements(),
                        registrationInformation);
        Response[] responses = joinProcess.getResponses(verifyProcess.getChallenge());
        assertTrue(verifyProcess.verify(responses), "expected join verification to have worked");
        clarcUser.finishRegistration(verifyProcess.getResponse());
        clarcIdentity = clarcUser.createIdentity();

        final PedersenCommitmentScheme commitmentScheme =
                PublicParametersFactory.getSingleMessageCommitmentScheme(clarcPublicParameters);

        final MessageBlock usk;

        MessageBlock msg = new MessageBlock();
        PedersenOpenValue pseudonymSecret = clarcIdentity.getPseudonymSecret();
        Arrays.stream(pseudonymSecret.getMessages()).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));

        PedersenCommitmentValue commitmentValue = clarcIdentity.getPseudonym().getCommitmentValue();
        if (commitmentScheme.verify(commitmentValue, pseudonymSecret, msg)) {
            usk = msg;
        } else {
            throw new IllegalArgumentException("The given pseudonym secret is not valid for the pseudonym.");
        }
        clarcUserSecret = new UserSecret((Zp.ZpElement) ((RingElementPlainText) usk.get(0)).getRingElement());
    }


    public SystemManagerKeyPair getSystemManagerKeyPair() {
        return clarcSystemManagerKeyPair;
    }

    public User getUser() {
        return clarcUser;
    }

    public UserPublicKey getFixedUpk() {
        return clarcUser.getPublicKey();
    }

    public UserSecret getUserSecret() {
        return clarcUserSecret;
    }

    public UserKeyPair getFixedUserKeyPair() {
        return new UserKeyPair(getFixedUpk(), getUserSecret());
    }

    public RegistrationInformation getRegistrationInformation() {
        return registrationInformation;
    }

    public SystemManager getSystemManager() {
        return systemManager;
    }

    public Identity getIdentity() {
        return clarcIdentity;
    }

    public static UserSecret extractUserSecretFromIdentity(PublicParameters clarcPublicParameters,
                                                           Identity clarcIdentity) {
        final PedersenCommitmentScheme commitmentScheme =
                PublicParametersFactory.getSingleMessageCommitmentScheme(clarcPublicParameters);
        final MessageBlock usk;

        MessageBlock msg = new MessageBlock();
        PedersenOpenValue pseudonymSecret = clarcIdentity.getPseudonymSecret();
        Arrays.stream(pseudonymSecret.getMessages()).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));

        PedersenCommitmentValue commitmentValue = clarcIdentity.getPseudonym().getCommitmentValue();
        if (commitmentScheme.verify(commitmentValue, pseudonymSecret, msg)) {
            usk = msg;
        } else {
            throw new IllegalArgumentException("The given pseudonym secret is not valid for the pseudonym.");
        }
        return new UserSecret((Zp.ZpElement) ((RingElementPlainText) usk.get(0)).getRingElement());
    }
}
