package de.upb.crypto.clarc.acs.pseudonym.impl.clarc;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

public class Identity extends de.upb.crypto.clarc.acs.pseudonym.Identity {
    @Represented
    private Pseudonym pseudonym;

    public Identity(PedersenCommitmentPair commitment) {
        super(commitment);
        pseudonym = new Pseudonym(commitment.getCommitmentValue());
    }

    public Identity(Representation representation) {
        super(representation);
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public Pseudonym getPseudonym() {
        return pseudonym;
    }

    @Override
    public PedersenOpenValue getPseudonymSecret() {
        return (PedersenOpenValue) commitment.getOpenValue();
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
