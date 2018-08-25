package de.upb.crypto.clarc.acs.pseudonym;

import de.upb.crypto.craco.commitment.interfaces.CommitmentPair;
import de.upb.crypto.craco.commitment.interfaces.OpenValue;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

/**
 * An {@link Identity} represents the private part of an user's identity. A user can decide to construct an arbitrary
 * amount of {@link Identity}s which can not be linked with each other, if one gets to know only the {@link Pseudonym}
 * of the corresponding {@link Identity}.
 * <br>
 * <b>This must never be shared with others, as it contains information which allow reconstruction of the
 * {@link de.upb.crypto.clarc.acs.user.UserSecret}. If one wants to communicate with another entity, the
 * {@link Pseudonym}
 * associated with this {@link Identity} must be shared instead.</b>
 * <br>
 * The secret information contained in the {@link Identity} can be retrieved by {@link Identity#getPseudonymSecret}
 * and is to be used to prove the validity and integrity of the transmitted {@link Pseudonym}.
 */
public abstract class Identity implements StandaloneRepresentable {
    @Represented
    protected CommitmentPair commitment;

    public Identity(CommitmentPair commitment) {
        this.commitment = commitment;
    }

    public Identity(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public abstract Pseudonym getPseudonym();

    public OpenValue getPseudonymSecret() {
        return commitment.getOpenValue();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Identity clarcIdentity = (Identity) o;
        return Objects.equals(commitment, clarcIdentity.commitment);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitment);
    }
}
