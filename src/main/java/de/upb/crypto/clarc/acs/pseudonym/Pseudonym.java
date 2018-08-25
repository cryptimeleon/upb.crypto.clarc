package de.upb.crypto.clarc.acs.pseudonym;

import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

/**
 * A {@link Pseudonym} represents the public part of an user's identity.
 * <p>
 * This is intended to be shared with any communication partner without revealing information about the users
 * {@link Identity} nor {@link de.upb.crypto.clarc.acs.user.UserSecret}.
 * <p>
 * The corresponding secret retrieved by {@link Identity#getPseudonymSecret} can be used to prove the validity and
 * integrity of the transmitted {@link Pseudonym}.
 */
public abstract class Pseudonym implements StandaloneRepresentable {

    @Represented
    protected CommitmentValue commitmentValue;

    public Pseudonym(CommitmentValue commitmentValue) {
        this.commitmentValue = commitmentValue;
    }

    public Pseudonym(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public CommitmentValue getCommitmentValue() {
        return commitmentValue;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Pseudonym pseudonym = (Pseudonym) o;
        return Objects.equals(commitmentValue, pseudonym.commitmentValue);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitmentValue);
    }
}
