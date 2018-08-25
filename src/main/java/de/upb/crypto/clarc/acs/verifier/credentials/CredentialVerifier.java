package de.upb.crypto.clarc.acs.verifier.credentials;

import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.protocols.ProtocolParameters;
import de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.interfaces.signature.Signature;

/**
 * Interface for proving a simple execution of a verification process
 */
public interface CredentialVerifier {
    /**
     * Initializes the verification process of a user
     *
     * @param protocolParameters the parameters for the protocol execution, as provided by the user
     * @param announcements      the announcements which were picked by the user
     * @param policyInformation  all information related to the policy to be fulfilled
     * @return A verification process which provides the API for the future communication with the user in order to
     * verify that the users credentials satisfy a known policy
     */
    InteractiveVerificationProcess initInteractiveVerificationProcess(ProtocolParameters protocolParameters,
                                                                      Announcement[] announcements,
                                                                      PolicyInformation policyInformation,
                                                                      Signature masterCredential);


    VerificationResult verifyNonInteractiveProof(NonInteractivePolicyProof proof, PolicyInformation policyInformation);
}
