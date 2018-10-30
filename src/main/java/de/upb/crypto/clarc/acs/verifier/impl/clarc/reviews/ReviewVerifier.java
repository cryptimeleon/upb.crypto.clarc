package de.upb.crypto.clarc.acs.verifier.impl.clarc.reviews;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewTokenIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.RateVerifyProtocolFactory;
import de.upb.crypto.clarc.acs.review.impl.clarc.Review;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManager;
import de.upb.crypto.clarc.acs.systemmanager.impl.clarc.SystemManagerPublicIdentity;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirVerificationKey;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocolProvider;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.mappings.BilinearMap;
import de.upb.crypto.math.interfaces.mappings.PairingProductExpression;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import static de.upb.crypto.clarc.acs.protocols.impl.clarc.ComputeRatingPublicKeyAndItemHashHelper.getHashedRatingPublicKeyAndItem;

/**
 * Implementation the actor responsible for the issuing of ratings and also for the linking and verifying of ratings.
 */
public class ReviewVerifier implements de.upb.crypto.clarc.acs.verifier.reviews.ReviewVerifier {
    private PublicParameters pp;
    private SystemManagerPublicIdentity systemManagerPublicIdentity;

    private PSExtendedVerificationKey raterPublicKey;

    /**
     * Initializes The ReviewVerifier with the linkability basis from the SystemManager
     * {@link SystemManager}.
     *
     * @param pp                              The acs public parameters
     * @param systemManagerPublicIdentity     The public identity of the system manager which contains the linkability
     *                                        information used for linking two reviews
     * @param reviewTokenIssuerPublicIdentity Public identity of the token issuer
     */
    public ReviewVerifier(PublicParameters pp,
                          SystemManagerPublicIdentity systemManagerPublicIdentity,
                          ReviewTokenIssuerPublicIdentity reviewTokenIssuerPublicIdentity) {
        this.pp = pp;
        this.systemManagerPublicIdentity = systemManagerPublicIdentity;

        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        this.raterPublicKey = signatureScheme.getVerificationKey(reviewTokenIssuerPublicIdentity.getIssuerPublicKey());
    }

    /**
     * This method checks if two reviews are from the same user, so it tries to "link" two different reviews to a
     * single user.
     *
     * @param review1 First review
     * @param review2 Second review
     * @return Returns whether the reviews are from the same user or not.
     */
    @Override
    public boolean areFromSameUser(de.upb.crypto.clarc.acs.review.Review review1, de.upb.crypto.clarc.acs.review.Review review2) {
        if (!verify(review1) || !verify(review2)) {
            return false;
        }
        Review firstReview = (Review) review1;
        Review secondReview = (Review) review2;

        GroupElement L1 = firstReview.getL1();
        GroupElement L2 = firstReview.getL2();

        GroupElement L1star = secondReview.getL1();
        GroupElement L2star = secondReview.getL2();

        BilinearMap map = pp.getBilinearMap();
        GroupElement leftSide = map.apply(L1.op(L1star.inv()), systemManagerPublicIdentity.getLinkabilityBasis());

        ReviewToken token = new ReviewToken(
                ((Review) review1).getBlindedTokenSignature(),
                ((Review) review1).getItem(),
                raterPublicKey);

        GroupElement hash = getHashedRatingPublicKeyAndItem(token, pp);

        GroupElement rightSide = map.apply(hash, L2.op(L2star.inv()));
        return leftSide.equals(rightSide);
    }

    /**
     * This method checks if the signature within the review is valid by using the {@link FiatShamirSignatureScheme}
     * and the {@link RateVerifyProtocolFactory}.
     *
     * @param review The review to check
     * @return whether the signature is valid or not
     */
    @Override
    public boolean verify(de.upb.crypto.clarc.acs.review.Review review) {
        if (!(review instanceof Review)) {
            throw new IllegalArgumentException("Expected Review");
        }
        Review clarcReview = (Review) review;

        ReviewToken token = new ReviewToken(clarcReview.getBlindedTokenSignature(),
                clarcReview.getItem(),
                clarcReview.getRaterPublicKey());
        RateVerifyProtocolFactory factory = new RateVerifyProtocolFactory(pp,
                clarcReview.getBlindedRegistrationInformation(),
                clarcReview.getSystemManagerPublicKey(),
                systemManagerPublicIdentity.getLinkabilityBasis(),
                token,
                clarcReview.getL1(),
                clarcReview.getL2());
        GeneralizedSchnorrProtocol rateVerifyProtocol = factory.getProtocol();
        GeneralizedSchnorrProtocolProvider protocolProvider = new GeneralizedSchnorrProtocolProvider(pp.getZp());
        FiatShamirSignatureScheme signatureScheme =
                new FiatShamirSignatureScheme(protocolProvider, new SHA256HashFunction());
        FiatShamirVerificationKey verificationKey = new FiatShamirVerificationKey(rateVerifyProtocol.getProblems());
        return signatureScheme.verify(clarcReview.getMessage(), clarcReview.getRatingSignature(), verificationKey);
    }

    /**
     * This method computes the group element {@code e( H(rpk, item), b )^usk} for linking base b, rating public key
     * rpk and item identifier item.
     * <p>
     * This element enables an efficient check whether a user (identified by usk) already published an rating for an
     * item (identified by (rpk, item)). This is motivated by the fact that this check would need O(n^2) comparisons
     * when using {@link #areFromSameUser(de.upb.crypto.clarc.acs.review.Review, de.upb.crypto.clarc.acs.review.Review)},
     * where n is the number of review in the database. Using the linking tag the only thing the database now needs to
     * do is store the tag along with the review. Whenever a new review is supposed to be published, one only needs to
     * compute the linking tag and compares it with the tags already stored. If there is a duplicate, the rating should
     * not be accepted. Otherwise, review and tag should be stored in the database for future duplicate checks.
     *
     * @param review
     *              the linking tag is to computed for
     * @return {@code e( H(rpk, item), b )^usk}
     */
    public GroupElement getLinkingTag(Review review) {
        if (!verify(review)) {
            throw new IllegalArgumentException("The given review is not valid!");
        }

        // L1 = H^{zeta + usk}
        GroupElement L1 = review.getL1();
        // L2 = b^zeta
        GroupElement L2 = review.getL2();

        ReviewToken token = new ReviewToken(
                                review.getBlindedTokenSignature(),
                                review.getItem(),
                                raterPublicKey
                            );

        GroupElement hash = getHashedRatingPublicKeyAndItem(token, pp);

        PairingProductExpression output = pp.getBilinearMap().pairingProductExpression();
        // e(L1, b) = e(H(rpk, item)^{zeta + usk}, b) = e(H(rpk, item), b)^{zeta} * e(H(rpk, item), b)^{usk}
        output.op(L1, systemManagerPublicIdentity.getLinkabilityBasis());
        // e(H(rpk, item), b^zeta)^{-1} = e(H(rpk, item), b)^{-zeta}
        output.op(hash, L2, BigInteger.valueOf(-1));

        // output = e(H(rpk, item), b)^{usk}
        return output.evaluate();
    }
}
