package de.upb.crypto.clarc.acs.pseudonym.impl.clarc;

import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.serialization.Representation;

public class Pseudonym extends de.upb.crypto.clarc.acs.pseudonym.Pseudonym {

    public Pseudonym(PedersenCommitmentValue commitment) {
        super(commitment);
    }

    public Pseudonym(Representation representation) {
        super(representation);
    }

    @Override
    public PedersenCommitmentValue getCommitmentValue() {
        return (PedersenCommitmentValue) commitmentValue;
    }

}
