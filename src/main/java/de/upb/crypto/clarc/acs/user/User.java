package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.issuer.InteractiveIssueIssuableProcess;
import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.Issuer;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewTokenIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.pseudonym.Identity;
import de.upb.crypto.clarc.acs.review.Review;
import de.upb.crypto.clarc.acs.user.credentials.CredentialNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.user.credentials.InteractiveRequestCredentialProcess;
import de.upb.crypto.clarc.acs.user.credentials.SignatureCredential;
import de.upb.crypto.clarc.acs.user.reviewtokens.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.clarc.acs.user.reviewtokens.ReviewTokeIssueanceState;
import de.upb.crypto.clarc.acs.verifier.credentials.VerifierPublicIdentity;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

import java.util.List;

/**
 * Provides a simple interface for initializing user related tasks in the credential system
 */
public interface User<CredentialType extends SignatureCredential, ReviewTokenType extends RepresentableReviewToken>
        extends StandaloneRepresentable {
    /**
     * Initializes the proving process of a policy satisfaction
     *
     * @param identity          The pseudonym under which the policy should be proven
     * @param policyInformation all information related to the policy to be fulfilled
     * @return A proving process which provides the API for the future communication with the verifier in order to
     * prove the the given policy is satisfied.
     */
    InteractiveProvingProcess initInteractiveProvingProcess(Identity identity,
                                                            PolicyInformation policyInformation);

    /**
     * Initializes the non-interactive proving process of a policy satisfaction
     *
     * @param identity          The pseudonym under which the policy should be proven
     * @param policyInformation all information related to the policy to be fulfilled
     * @return a non-interactive proof of policy fulfillment which can be publicly verified
     */
    NonInteractivePolicyProof createNonInteractivePolicyProof(Identity identity,
                                                              PolicyInformation policyInformation,
                                                              VerifierPublicIdentity verifierIdentity);

    /**
     * Initializes the interactive issuing process to obtain a {@link SignatureCredential} from an {@link Issuer}
     * signing the given {@link Attributes}. The contained proof is executed between this and the corresponding
     * {@link InteractiveIssueIssuableProcess}. On successful execution, the {@link IssueResponse} is returned by the
     * {@link Issuer} to be received by {@link User#receiveCredentialInteractively}.
     *
     * @param issuerPublicIdentity the issuer's public identity
     * @param identity             the {@link Identity} to use during interaction with the {@link Issuer}
     * @param issuable             the attributes to be signed by the issuer
     * @return an interactive proof which results in an retrievable {@link SignatureCredential} on success
     */
    InteractiveRequestCredentialProcess createInteractiveIssueCredentialRequest(
            CredentialIssuerPublicIdentity issuerPublicIdentity,
            Identity identity,
            Attributes issuable);

    /**
     * Initializes the non-interactive issuing process to obtain a {@link SignatureCredential} from an {@link Issuer}
     * signing the given {@link Attributes}. On successful verification of the non-interactive proof, the
     * {@link IssueResponse} is returned by the {@link Issuer} to be received by
     * {@link User#receiveCredentialNonInteractively}.
     *
     * @param issuerPublicIdentity the issuer's public identity
     * @param identity             the {@link Identity} to use during interaction with the {@link Issuer}
     * @param issuable             the attributes to be signed by the issuer
     * @return non-interactive proof which results in an retrievable {@link SignatureCredential} on successful
     * verification
     */
    CredentialNonInteractiveResponseHandler createNonInteractiveIssueCredentialRequest(
            CredentialIssuerPublicIdentity issuerPublicIdentity,
            Identity identity,
            Attributes issuable);

    /**
     * Initializes the interactive issuing process to obtain a {@link RepresentableReviewToken} from an {@link Issuer}
     * granting the permission to rate for the given review subject. The contained proof is executed between this
     * and the corresponding {@link InteractiveIssueIssuableProcess}. On successful execution, the {@link IssueResponse}
     * is returned by the  {@link Issuer} to be received by {@link User#receiveReviewTokenInteractively}.
     *
     * @param issuerPublicIdentity the issuer's public identity
     * @param identity             the {@link Identity} to use during interaction with the {@link Issuer}
     * @param reviewSubject        the review subject data
     * @return an interactive proof which results in an retrievable {@link RepresentableReviewToken} on success
     */
    InteractiveRequestReviewTokenProcess createInteractiveIssueReviewTokenRequest(
            ReviewTokenIssuerPublicIdentity issuerPublicIdentity,
            Identity identity,
            byte... reviewSubject);

    /**
     * Initializes the interactive issuing process to obtain a {@link RepresentableReviewToken} from an {@link Issuer}
     * granting the permission to rate for the given {@link HashOfItem}. On successful verification of the
     * non-interactive proof, the {@link IssueResponse} is returned by the {@link Issuer} to be received by
     * {@link User#receiveReviewTokenNonInteractively}.
     *
     * @param reviewTokenIssuerPublicIdentity the issuer's public identity
     * @param identity                        the {@link Identity} to use during interaction with the {@link Issuer}
     * @param reviewSubject                   the review subject data
     * @return non-interactive proof which results in an retrievable {@link RepresentableReviewToken} on successful
     * verification
     */
    ReviewTokeIssueanceState createNonInteractiveIssueReviewTokenRequest(
            ReviewTokenIssuerPublicIdentity reviewTokenIssuerPublicIdentity,
            Identity identity,
            byte... reviewSubject);

    /**
     * Receive the {@link SignatureCredential} returned by the {@link Issuer} after successful execution of the
     * interactive proof created by {@link User#createInteractiveIssueCredentialRequest} and the corresponding
     * {@link InteractiveIssueIssuableProcess}.
     *
     * @param issuanceProcess issuing process created by {@link User#createInteractiveIssueCredentialRequest}
     * @param issueResponse   response sent by the {@link Issuer}
     */
    void receiveCredentialInteractively(InteractiveRequestCredentialProcess issuanceProcess,
                                        IssueResponse<CredentialType> issueResponse);

    /**
     * Receive the {@link SignatureCredential} returned by the {@link Issuer} after successful verification of the
     * non-interactive proof created by {@link User#createNonInteractiveIssueCredentialRequest}
     *
     * @param request       response handler created by {@link User#createNonInteractiveIssueCredentialRequest}
     * @param issueResponse response sent by the {@link Issuer}
     */
    void receiveCredentialNonInteractively(CredentialNonInteractiveResponseHandler request,
                                           IssueResponse<CredentialType> issueResponse);


    /**
     * Receive the {@link SignatureCredential} returned by the {@link Issuer} after successful execution of the
     * interactive proof created by {@link User#createInteractiveIssueCredentialRequest} and the corresponding
     * {@link InteractiveIssueIssuableProcess}.
     *
     * @param requestReviewTokenProcess issuing process created by {@link User#createInteractiveIssueReviewTokenRequest}
     * @param issueResponse             response sent by the {@link Issuer}
     */
    void receiveReviewTokenInteractively(InteractiveRequestReviewTokenProcess requestReviewTokenProcess,
                                         IssueResponse<ReviewTokenType> issueResponse);

    /**
     * Receive the {@link SignatureCredential} returned by the {@link Issuer} after successful verification of the
     * non-interactive proof created by {@link User#createNonInteractiveIssueReviewTokenRequest}.
     *
     * @param request       issuing process created by {@link User#createNonInteractiveIssueReviewTokenRequest}
     * @param issueResponse response sent by the {@link Issuer}
     */
    void receiveReviewTokenNonInteractively(ReviewTokeIssueanceState request,
                                            IssueResponse<ReviewTokenType> issueResponse);

    /**
     * Create a new review while automatically picking a matching review token from the previously registered tokens
     *
     * @param message                         the message with the review content
     * @param reviewTokenIssuerPublicIdentity the public identity of the token issuer
     * @param reviewSubject                   the subject of the review token
     * @return The {@link Review} for the given message
     */
    Review createReview(byte[] message,
                        ReviewTokenIssuerPublicIdentity reviewTokenIssuerPublicIdentity,
                        byte... reviewSubject);

    /**
     * Creates a review given a specific {@link ReviewToken}
     *
     * @param message the message with the review content
     * @param token   the token to use for creating the {@link Review}
     * @return The {@link Review} for the given message
     */
    Review createReview(byte[] message, ReviewToken token);


    /**
     * @return The public key of the user
     */
    UserPublicKey getPublicKey();

    Identity createIdentity();

    List<? extends Identity> getIdentities();

    /**
     * @return the credential which was issued by the {@link Issuer} with the given
     * {@link CredentialIssuerPublicIdentity}
     */
    CredentialType getCredential(CredentialIssuerPublicIdentity issuerPublicIdentity);
}
