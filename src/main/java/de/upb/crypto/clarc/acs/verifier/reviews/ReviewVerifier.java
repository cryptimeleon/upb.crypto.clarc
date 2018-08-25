package de.upb.crypto.clarc.acs.verifier.reviews;

import de.upb.crypto.clarc.acs.review.Review;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirSignatureScheme;

/**
 * This is an interface with the minimum functionalities an implementation of a ReviewVerifier should have.
 */
public interface ReviewVerifier {

    /**
     * This algorithm will check whether the review was created using the rate algorithm or not. This is done
     * by using the {@link FiatShamirSignatureScheme} and its verify algorithm.
     *
     * @param review The review to check
     * @return Whether the review is valid or not
     */
    boolean verify(Review review);

    boolean areFromSameUser(Review review1, Review review2);
}
