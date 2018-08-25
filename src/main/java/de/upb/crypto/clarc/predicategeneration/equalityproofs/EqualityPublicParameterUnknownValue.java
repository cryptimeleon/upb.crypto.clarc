package de.upb.crypto.clarc.predicategeneration.equalityproofs;

import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import javax.annotation.CheckReturnValue;
import java.util.Objects;

/**
 * This construction is used for {@link PredicateTypePrimitive#EQUALITY_DLOG}, so if the dlog is not known
 */
public class EqualityPublicParameterUnknownValue extends EqualityPublicParameters {
    @UniqueByteRepresented
    @Represented(structure = "group2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g2;

    @UniqueByteRepresented
    @Represented(structure = "group2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement y;

    @Represented
    private Group group2;

    /**
     * Generate {@link EqualityPublicParameterUnknownValue} for an equality-proof (Section 5.1.1),
     * where s is equal to a not publicly known
     * <p>
     * Create a proof for generator ^ alpha = generator ^ equalDLog,
     * where  alpha is the value inside the commitment.
     *
     * @param pedersenPP                of the commitment scheme used to generate the commitment on the announcement
     * @param commitment                commitment value C for the first commitment on alpha1
     * @param g2                        the second generator, used to compute the predefined value y, that the
     *                                  commitment needs to be equal to
     * @param y                         the predefined value, the commitment c is proven to be equal to
     * @param positionOfFirstCommitment position of alpha 1 in the credential / attribute space
     * @param zp                        Zp used in the system
     * @param type                      the predicate proof type
     */
    public EqualityPublicParameterUnknownValue(PedersenPublicParameters pedersenPP, GroupElement commitment,
                                               GroupElement g2, GroupElement y, int positionOfFirstCommitment,
                                               Zp zp, PredicateTypePrimitive type) {
        super(pedersenPP, positionOfFirstCommitment, -1, zp, type);
        this.g2 = g2;
        this.y = y;
        this.group2 = g2.getStructure();
        super.setCommitment(commitment);
    }

    /**
     * Generate {@link EqualityPublicParameterUnknownValue} for an equality-proof (Section 5.1.1),
     * where s is equal to a not publicly known
     * <p>
     * Create a proof for generator ^ alpha = generator ^ equalDLog,
     * where  alpha is the value inside the commitment.
     *
     * @param pedersenPP                of the commitment scheme used to generate the commitment on the announcement
     * @param g2                        the second generator, used to compute the predefined value y, that the
     *                                  commitment needs to be equal to
     * @param y                         the predefined value, the commitment c is proven to be equal to
     * @param positionOfFirstCommitment position of alpha 1 in the credential / attribute space
     * @param zp                        Zp used in the system
     * @param type                      the predicate proof type
     */
    public EqualityPublicParameterUnknownValue(PedersenPublicParameters pedersenPP, GroupElement g2, GroupElement y,
                                               int positionOfFirstCommitment,
                                               Zp zp, PredicateTypePrimitive type) {
        super(pedersenPP, positionOfFirstCommitment, -1, zp, type);
        this.g2 = g2;
        this.y = y;
        this.group2 = g2.getStructure();
    }

    public EqualityPublicParameterUnknownValue(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    @CheckReturnValue
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement getG2() {
        return g2;
    }

    public GroupElement getY() {
        return y;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        EqualityPublicParameterUnknownValue that = (EqualityPublicParameterUnknownValue) o;
        return Objects.equals(getG2(), that.getG2()) &&
                Objects.equals(getY(), that.getY());
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), getG2(), getY(), group2);
    }
}