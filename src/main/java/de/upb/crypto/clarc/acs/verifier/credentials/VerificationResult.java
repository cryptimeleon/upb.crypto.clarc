package de.upb.crypto.clarc.acs.verifier.credentials;

import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.StandaloneRepresentable;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

public class VerificationResult implements StandaloneRepresentable {
    @Represented
    private boolean verify;
    @Represented
    private FiatShamirProof proof;
    @Represented
    private PolicyInformation policyInformation;
    @Represented
    private Pseudonym pseudonym;
    @Represented
    private RepresentableSignature blindedMasterCredential;

    public VerificationResult(boolean verify, FiatShamirProof proof, PolicyInformation policyInformation, Pseudonym pseudonym, RepresentableSignature blindedMasterCredential) {
        this.verify = verify;
        this.proof = proof;
        this.policyInformation = policyInformation;
        this.pseudonym = pseudonym;
        this.blindedMasterCredential = blindedMasterCredential;
    }

    public VerificationResult(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public boolean isVerify() {
        return verify;
    }

    public FiatShamirProof getFiatShamirProof() {
        return proof;
    }

    public Pseudonym getPseudonym() {
        return pseudonym;
    }

    public RepresentableSignature getBlindedMasterCredential() {
        return blindedMasterCredential;
    }

    public PolicyInformation getPolicyInformation() {
        return policyInformation;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        VerificationResult that = (VerificationResult) o;
        return verify == that.verify &&
                Objects.equals(proof, that.proof) &&
                Objects.equals(policyInformation, that.policyInformation) &&
                Objects.equals(pseudonym, that.pseudonym) &&
                Objects.equals(blindedMasterCredential, that.blindedMasterCredential);
    }

    @Override
    public int hashCode() {
        return Objects.hash(verify, proof, policyInformation, pseudonym, blindedMasterCredential);
    }
}
