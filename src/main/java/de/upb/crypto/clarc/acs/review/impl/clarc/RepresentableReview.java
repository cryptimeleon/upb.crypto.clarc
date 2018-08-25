package de.upb.crypto.clarc.acs.review.impl.clarc;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;

import java.util.Objects;

/**
 * This class provides is used to create Reviews which are StandaloneRepresentable. Instead of directly making
 * {@link Review} StandaloneRepresentable, this class recreates an Review since only parameters from
 * the public parameters are needed for that. This prevents the Review class to have multiple class variables
 * only used for the recreation.
 */
public class RepresentableReview implements de.upb.crypto.clarc.acs.review.RepresentableReview {
    private Representation review;

    public RepresentableReview(Review review) {
        this.review = review.getRepresentation();
    }

    public RepresentableReview(Representation representation) {
        review = representation.obj().get("review");
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = new ObjectRepresentation();
        object.put("review", review);
        return object;
    }

    @Override
    public Review getReview(PublicParameters pp) {
        return new Review(review, pp);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RepresentableReview that = (RepresentableReview) o;
        return Objects.equals(review, that.review);
    }

    @Override
    public int hashCode() {
        return Objects.hash(review);
    }
}
