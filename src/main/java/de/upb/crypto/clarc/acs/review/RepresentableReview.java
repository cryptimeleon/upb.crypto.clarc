package de.upb.crypto.clarc.acs.review;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * This is the interface for the StandaloneRepresentable variant of the Reviews. The implementations then need to
 * implement the getReview method which reconstructs the review using the public parameters.
 */
public interface RepresentableReview extends StandaloneRepresentable {
    Review getReview(PublicParameters pp);
}
