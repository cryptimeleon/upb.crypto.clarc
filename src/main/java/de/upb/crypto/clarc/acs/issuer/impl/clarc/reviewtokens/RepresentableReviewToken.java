package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

/**
 * This class is used to get ReviewTokens to be StandaloneRepresentable. Normally, multiple class variables would
 * be needed only for the recreation of a ReviewToken from a representation. But since all of them are within the
 * public parameters, this is encapsulated here.
 */
public class RepresentableReviewToken implements de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken {
    private Representation reviewToken;

    public RepresentableReviewToken(ReviewToken reviewToken) {
        this.reviewToken = reviewToken.getRepresentation();
    }

    public RepresentableReviewToken(Representation representation) {
        reviewToken = representation.obj().get("reviewToken");
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = new ObjectRepresentation();
        object.put("reviewToken", reviewToken);
        return object;
    }

    /**
     * This method constructs a ReviewToken from the representable version within this object and the
     * public parameters.
     *
     * @param pp public parameters of the ACS
     * @return ReviewToken with the same data as this RepresentableReviewToken
     */
    @Override
    public ReviewToken getReviewToken(PublicParameters pp) {
        return new ReviewToken(reviewToken, pp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RepresentableReviewToken that = (RepresentableReviewToken) o;
        return Objects.equals(reviewToken, that.reviewToken);
    }

    @Override
    public int hashCode() {
        return Objects.hash(reviewToken);
    }
}
