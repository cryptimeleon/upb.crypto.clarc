package de.upb.crypto.clarc.acs;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.InteractiveIssueReviewTokenProcess;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuer;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Identity;
import de.upb.crypto.clarc.acs.review.Review;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.InteractiveJoinVerifyProcess;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.acs.user.InteractiveJoinProcess;
import de.upb.crypto.clarc.acs.user.impl.clarc.User;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.InteractiveRequestReviewTokenProcess;
import de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken.ReviewTokenNonInteractiveResponseHandler;
import de.upb.crypto.clarc.acs.verifier.impl.clarc.reviews.ReviewVerifier;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class ReputationSystemTest {
    @Test
    void nonInteractiveRateVerifyTest() {
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        PublicParameters pp = ppFactory.create();
        assertNotNull(pp, "pp");
        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);

        User clarcUser = new User(pp);

        SystemManager systemManager = new SystemManager(pp);
        assertNotNull(systemManager.getPublicIdentity(), "public identity of systemManager");

        InteractiveJoinProcess joinProcess = clarcUser.initInteractiveJoinProcess(systemManager.getPublicIdentity());
        Announcement[] joinAnnouncements = joinProcess.getAnnouncements();
        InteractiveJoinVerifyProcess interactiveJoinVerifyProcess = systemManager
                .initInteractiveJoinVerifyProcess(clarcUser.getPublicKey(), joinAnnouncements,
                        joinProcess.getRegistrationInformation());
        Response[] joinResponses = joinProcess.getResponses(interactiveJoinVerifyProcess.getChallenge());
        assertTrue(interactiveJoinVerifyProcess.verify(joinResponses), "the joining protocol should have worked");
        clarcUser.finishRegistration(interactiveJoinVerifyProcess.getResponse());

        assertEquals(0, clarcUser.getIdentities().size(), "expected no pseudonym to exist");
        clarcUser.createIdentity();
        assertEquals(1, clarcUser.getIdentities().size(), "expected pseudonym to be generated");
        Identity identity = clarcUser.getIdentities().get(0);

        ReviewTokenIssuer reviewTokenIssuer = new ReviewTokenIssuer(pp);
        ReviewVerifier reviewVerifier =
                new ReviewVerifier(pp, systemManager.getPublicIdentity(), reviewTokenIssuer.getPublicIdentity());

        final ReviewTokenNonInteractiveResponseHandler reviewTokenResponseHandler =
                clarcUser.createNonInteractiveIssueReviewTokenRequest(reviewTokenIssuer.getPublicIdentity(),
                        identity, "123".getBytes());
        final ReviewTokenIssueResponse nonInteractiveReviewTokenResponse =
                reviewTokenIssuer.issueNonInteractively(reviewTokenResponseHandler.getRequest());
        clarcUser.receiveReviewTokenNonInteractively(reviewTokenResponseHandler, nonInteractiveReviewTokenResponse);

        Review review1 = clarcUser.createReview(
                "This item was awesome".getBytes(),
                reviewTokenIssuer.getPublicIdentity(),
                "123".getBytes()
        );
        assertNotNull(review1, "review should not ne null");

        assertTrue(reviewVerifier.verify(review1), "verification should have worked");

    }

    @Test
    void rateAndVerifyTest() {
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        PublicParameters pp = ppFactory.create();
        assertNotNull(pp, "pp");
        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);

        User clarcUser = new User(pp);

        SystemManager systemManager = new SystemManager(pp);
        final SystemManagerPublicIdentity systemManagerPublicIdentity = systemManager.getPublicIdentity();
        assertNotNull(systemManagerPublicIdentity, "public identity of systemManager");

        InteractiveJoinProcess joinProcess = clarcUser.initInteractiveJoinProcess(systemManagerPublicIdentity);
        Announcement[] joinAnnouncements = joinProcess.getAnnouncements();
        InteractiveJoinVerifyProcess interactiveJoinVerifyProcess = systemManager
                .initInteractiveJoinVerifyProcess(clarcUser.getPublicKey(), joinAnnouncements,
                        joinProcess.getRegistrationInformation());
        Response[] joinResponses = joinProcess.getResponses(interactiveJoinVerifyProcess.getChallenge());
        assertTrue(interactiveJoinVerifyProcess.verify(joinResponses), "the joining protocol should have worked");
        clarcUser.finishRegistration(interactiveJoinVerifyProcess.getResponse());

        assertEquals(0, clarcUser.getIdentities().size(), "expected no pseudonym to exist");
        clarcUser.createIdentity();
        assertEquals(1, clarcUser.getIdentities().size(), "expected pseudonym to be generated");
        Identity identity = clarcUser.getIdentities().get(0);

        ReviewTokenIssuer reviewTokenIssuer = new ReviewTokenIssuer(pp);
        ReviewVerifier reviewVerifier =
                new ReviewVerifier(pp, systemManagerPublicIdentity, reviewTokenIssuer.getPublicIdentity());

        final InteractiveRequestReviewTokenProcess requestReviewTokenProcess1 =
                clarcUser.createInteractiveIssueReviewTokenRequest(
                        reviewTokenIssuer.getPublicIdentity(),
                        identity,
                        "123".getBytes()
                );
        final Announcement[] announcements1 = requestReviewTokenProcess1.getAnnouncements();
        final InteractiveIssueReviewTokenProcess issueReviewTokenProcess1 =
                reviewTokenIssuer.initInteractiveIssueProcess(
                        requestReviewTokenProcess1.getUskCommitmentValue(),
                        identity.getPseudonym(),
                        requestReviewTokenProcess1.getIssuable(), announcements1);
        final Response[] responses1 = requestReviewTokenProcess1.getResponses(issueReviewTokenProcess1.getChallenge());
        assertTrue(issueReviewTokenProcess1.verify(responses1),
                "Verification of first review token request should have worked");

        clarcUser.receiveReviewTokenInteractively(requestReviewTokenProcess1, issueReviewTokenProcess1
                .getIssueResponse());

        final InteractiveRequestReviewTokenProcess requestReviewTokenProcess2 =
                clarcUser.createInteractiveIssueReviewTokenRequest
                        (reviewTokenIssuer.getPublicIdentity(), identity, "123".getBytes());
        final Announcement[] announcements2 = requestReviewTokenProcess2.getAnnouncements();
        final InteractiveIssueReviewTokenProcess issueReviewTokenProcess2 =
                reviewTokenIssuer.initInteractiveIssueProcess
                        (requestReviewTokenProcess2.getUskCommitmentValue(),
                                identity.getPseudonym(),
                                requestReviewTokenProcess2.getIssuable(), announcements2);
        final Response[] responses2 = requestReviewTokenProcess2.getResponses(issueReviewTokenProcess2.getChallenge());
        assertTrue(issueReviewTokenProcess2.verify(responses2),
                "Verification of second review token request should have worked");

        clarcUser.receiveReviewTokenInteractively(requestReviewTokenProcess2, issueReviewTokenProcess2
                .getIssueResponse());

        ReviewToken reviewToken1 =
                clarcUser.getReviewTokens(reviewTokenIssuer.getPublicIdentity(), "123".getBytes())[0];
        de.upb.crypto.clarc.acs.review.impl.clarc.Review review1 = clarcUser.createReview("This item was awesome".getBytes(), reviewToken1);
        assertNotNull(review1, "review should not ne null");

        ReviewToken reviewToken2 =
                clarcUser.getReviewTokens(reviewTokenIssuer.getPublicIdentity(), "123".getBytes())[1];
        de.upb.crypto.clarc.acs.review.impl.clarc.Review review2 = clarcUser.createReview("This item was not awesome".getBytes(), reviewToken2);
        assertNotNull(review2, "review should not ne null");

        assertTrue(reviewVerifier.verify(review1), "verification should have worked");
        assertTrue(reviewVerifier.verify(review2), "verification should have worked");
        assertTrue(reviewVerifier.areFromSameUser(review1, review2), "reviews are from the same user");
        assertArrayEquals(reviewVerifier.getLinkingTag(review1), reviewVerifier.getLinkingTag(review2), "Linking tags are equal");
    }
}
