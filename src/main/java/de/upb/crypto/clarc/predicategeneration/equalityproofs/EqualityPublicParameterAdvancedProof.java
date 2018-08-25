package de.upb.crypto.clarc.predicategeneration.equalityproofs;

import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

/**
 * This advanced construction is used in case of {@link PredicateTypePrimitive#EQUALITY_PUBLIC_VALUE}
 */
public class EqualityPublicParameterAdvancedProof extends EqualityPublicParameters {

    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    @UniqueByteRepresented
    private Zp.ZpElement knownDlog;

    public EqualityPublicParameterAdvancedProof(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * Generate EqualityPublicParameter for an equality-proof (Section 5.1.2), where \alpha is equal to a publicly
     * known value
     * <p>
     * Create a proof for generator^alpha = generator^knownDlog,
     * where  alpha is the value inside the commitment.
     *
     * @param pedersenPP                of the commitment scheme used to generate the commitment on the announcement
     * @param knownDlog                 publicly known value, that alpha needs to be equal to
     * @param positionOfFirstCommitment position of alpha 1 in the credential / attribute space
     * @param type                      the predicate proof type
     */
    public EqualityPublicParameterAdvancedProof(PedersenPublicParameters pedersenPP, Zp.ZpElement knownDlog,
                                                int positionOfFirstCommitment, PredicateTypePrimitive type) {
        this(pedersenPP, knownDlog, positionOfFirstCommitment, -1, type);
    }

    /**
     * Generate  for an equality-proof (Section 5.1.3), where \alpha1 is equal to another commitment value \alpha2
     * <p>
     * Create a proof for generator^alpha1 = generator^alpha2
     * where  alpha is the value inside the commitment.
     *
     * @param pedersenPP                 of the commitment scheme used to generate the commitment on the announcement
     * @param knownDLog                  the value of the known dlog (or 0, for equality of two attributes)
     * @param positionOfFirstCommitment  position of alpha 1 in the credential / attribute space
     * @param positionOfSecondCommitment position of alpha 1 in the credential / attribute space
     * @param type                       the predicate proof type
     */
    public EqualityPublicParameterAdvancedProof(PedersenPublicParameters pedersenPP, Zp.ZpElement knownDLog,
                                                int positionOfFirstCommitment, int positionOfSecondCommitment,
                                                PredicateTypePrimitive type) {
        super(pedersenPP, positionOfFirstCommitment, positionOfSecondCommitment, knownDLog.getStructure(), type);
        this.knownDlog = knownDLog;
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public Zp.ZpElement getKnownDlog() {
        return knownDlog;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EqualityPublicParameterAdvancedProof that = (EqualityPublicParameterAdvancedProof) o;
        return Objects.equals(getKnownDlog(), that.getKnownDlog());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getKnownDlog());
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}