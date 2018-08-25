package de.upb.crypto.clarc.acs.systemmanager;

import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.clarc.acs.verifier.credentials.InteractiveVerificationProcess;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface SystemManager extends StandaloneRepresentable {
    de.upb.crypto.clarc.acs.user.UserPublicKey retrievePublicKey(VerificationResult verificationResult);

    InteractiveVerificationProcess initInteractiveJoinVerifyProcess(UserPublicKey userIdentity,
                                                                    Announcement[] announcements,
                                                                    RegistrationInformation registration);

    /**
     * @return the {@link SystemManagerPublicIdentity} of the system manager
     */
    SystemManagerPublicIdentity getPublicIdentity();
}
