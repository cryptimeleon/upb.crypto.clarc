package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.Issuable;
import de.upb.crypto.clarc.acs.pseudonym.Pseudonym;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * A request for the issuing of a credential
 */
public abstract class NonInteractiveIssuableRequest<IssuableType extends Issuable> implements StandaloneRepresentable {
    @Represented
    private CommitmentValue commitment;

    @Represented
    private Pseudonym pseudonym;

    @Represented
    private IssuableType issuable;

    @Represented
    private Proof proof;

    /**
     * Initalizes the request
     *
     * @param commitment The commitment on the usk
     * @param pseudonym  A pseudonym commitment
     * @param issuable   The issuable subject which is requested
     * @param proof      The proof which proves knowledge about the necessary secrets for requesting the credential
     */
    public NonInteractiveIssuableRequest(
            CommitmentValue commitment,
            Pseudonym pseudonym,
            IssuableType issuable,
            Proof proof) {
        this.commitment = commitment;
        this.pseudonym = pseudonym;
        this.issuable = issuable;
        this.proof = proof;
    }

    /**
     * Constructor for deserialization
     *
     * @param representation The serialized {@link Representation}
     */
    public NonInteractiveIssuableRequest(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * The commitment on the user secret
     *
     * @return The {@link CommitmentValue} of the user secret commitment
     */
    public CommitmentValue getCommitment() {
        return commitment;
    }

    /**
     * The used {@link Pseudonym} of the prover
     *
     * @return {@link Pseudonym} of the prover
     */
    public Pseudonym getPseudonym() {
        return pseudonym;
    }

    /**
     * The {@link Issuable} which the {@link User} requests an issuable object for
     *
     * @return Array of the {@link AttributeNameValuePair} objects for which a credential is requested for
     */
    public IssuableType getIssuable() {
        return issuable;
    }

    /**
     * The proof that the user knows the relevant secrets
     *
     * @return The {@link Proof} that the user knows the relevant secrets
     */
    public Proof getProof() {
        return proof;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NonInteractiveIssuableRequest that = (NonInteractiveIssuableRequest) o;
        return Objects.equals(commitment, that.commitment) &&
                Objects.equals(pseudonym, that.pseudonym) &&
                Objects.equals(issuable, that.issuable) &&
                Objects.equals(proof, that.proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(commitment, pseudonym, issuable, proof);
    }
}
