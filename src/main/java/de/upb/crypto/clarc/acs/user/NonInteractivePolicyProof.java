package de.upb.crypto.clarc.acs.user;

import de.upb.crypto.clarc.acs.protocols.ProtocolParameters;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.Proof;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public abstract class NonInteractivePolicyProof implements StandaloneRepresentable {

    @Represented
    private ProtocolParameters protocolParameters;

    @Represented
    private Proof proof;

    @Represented
    private RepresentableSignature masterCredential;

    /**
     * Initializes the object
     *
     * @param protocolParameters The parameters used to generate the protocol
     * @param proof              The proof which proves the fulfillment of a protocol
     * @param masterCredential   master credential
     */
    public NonInteractivePolicyProof(ProtocolParameters protocolParameters,
                                     Proof proof,
                                     RepresentableSignature masterCredential) {
        this.protocolParameters = protocolParameters;
        this.proof = proof;
        this.masterCredential = masterCredential;
    }

    public NonInteractivePolicyProof(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Getter for receiving the parameters necessary to instantiate the protocol
     *
     * @return The {@link ProtocolParameters} used to generate the proof
     */
    public ProtocolParameters getProtocolParameters() {
        return protocolParameters;
    }

    /**
     * Getter for receiving the actual proof
     *
     * @return The {@link Proof} which proves that a certain protocol is fulfilled
     */
    public Proof getProof() {
        return proof;
    }

    public RepresentableSignature getMasterCredential() {
        return masterCredential;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        NonInteractivePolicyProof that = (NonInteractivePolicyProof) o;
        return Objects.equals(protocolParameters, that.protocolParameters) &&
                Objects.equals(proof, that.proof);
    }

    @Override
    public int hashCode() {
        return Objects.hash(protocolParameters, proof);
    }
}
