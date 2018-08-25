package de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken;

import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.serialization.Representation;

/**
 * Clarc specific version of the {@link NonInteractiveIssuableRequest} for more type safe usage
 */
public class NonInteractiveReviewTokenRequest extends NonInteractiveIssuableRequest<HashOfItem> {
    public NonInteractiveReviewTokenRequest(
            PedersenCommitmentValue commitment,
            Pseudonym pseudonym,
            HashOfItem issuable,
            FiatShamirProof proof) {
        super(commitment, pseudonym, issuable, proof);
    }

    @Override
    public PedersenCommitmentValue getCommitment() {
        return (PedersenCommitmentValue) super.getCommitment();
    }

    @Override
    public Pseudonym getPseudonym() {
        return (Pseudonym) super.getPseudonym();
    }

    /**
     * Constructor for deserialization
     *
     * @param representation The serialized {@link Representation}
     */
    public NonInteractiveReviewTokenRequest(Representation representation) {
        super(representation);
    }
}
