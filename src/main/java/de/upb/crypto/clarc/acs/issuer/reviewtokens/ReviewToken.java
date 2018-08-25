package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.math.serialization.Representable;

/**
 * Note that this class only extends Representable. This means that the implementation also is not
 * StandaloneRepresentable. However, there is another class {@link RepresentableReviewToken} which wraps
 * this class to make it StandaloneRepresentable without having to save multiple Groups or similar things
 * only to recreate the object.
 */
public interface ReviewToken extends Representable {
}
