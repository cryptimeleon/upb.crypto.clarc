package de.upb.crypto.clarc.acs.issuer.reviewtokens;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

public interface RepresentableReviewToken extends StandaloneRepresentable {
    ReviewToken getReviewToken(PublicParameters pp);
}
