package de.upb.crypto.clarc.acs.user.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.user.NonInteractiveIssuableRequest;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.math.serialization.Representation;

/**
 * Clarc specific version of the {@link NonInteractiveIssuableRequest} for more type safe usage
 */
public class NonInteractiveCredentialRequest extends NonInteractiveIssuableRequest<Attributes> {
    public NonInteractiveCredentialRequest(
            PedersenCommitmentValue commitment,
            Pseudonym pseudonym,
            Attributes issuable,
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
    public NonInteractiveCredentialRequest(Representation representation) {
        super(representation);
    }
}
