package de.upb.crypto.clarc.acs.user.impl.clarc;

import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.ProtocolParameters;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.math.serialization.Representation;

/**
 * Clarc specific version of the {@link de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof} for more type safe usage
 */
public class NonInteractivePolicyProof extends de.upb.crypto.clarc.acs.user.NonInteractivePolicyProof {
    public NonInteractivePolicyProof(ProtocolParameters protocolParameters,
                                     FiatShamirProof proof,
                                     RepresentableSignature masterCredential) {
        super(protocolParameters, proof, masterCredential);
    }

    public NonInteractivePolicyProof(Representation representation) {
        super(representation);
    }

    @Override
    public ProtocolParameters getProtocolParameters() {
        return (ProtocolParameters) super.getProtocolParameters();
    }

    @Override
    public FiatShamirProof getProof() {
        return (FiatShamirProof) super.getProof();
    }
}
