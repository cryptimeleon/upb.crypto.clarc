package de.upb.crypto.clarc.predicategeneration.equalityproofs;

import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

public abstract class EqualityPublicParameters implements PredicatePublicParameters {

    @Represented
    protected Zp zp;

    @UniqueByteRepresented
    @Represented(structure = "group1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g1, h, commitment;

    @Represented
    private Group group1;

    @UniqueByteRepresented
    @Represented
    private int positionOfFirstCommitment, positionOfSecondCommitment;

    @UniqueByteRepresented
    @Represented
    private PredicateTypePrimitive type;

    protected EqualityPublicParameters(PedersenPublicParameters pedersenPP, int positionOfFirstCommitment,
                                       int positionOfSecondCommitment, Zp zp,
                                       PredicateTypePrimitive type) {
        this.g1 = pedersenPP.getG();
        this.h = pedersenPP.getH()[0];
        this.commitment = g1.getStructure().getNeutralElement();
        this.group1 = g1.getStructure();
        this.positionOfFirstCommitment = positionOfFirstCommitment;
        this.positionOfSecondCommitment = positionOfSecondCommitment;
        this.zp = zp;
        this.type = type;
    }

    protected EqualityPublicParameters() {
    }

    public GroupElement getG1() {
        return g1;
    }

    public GroupElement getH() {
        return h;
    }

    public GroupElement getCommitment() {
        return commitment;
    }

    public void setCommitment(GroupElement commitment) {
        this.commitment = commitment;
    }

    public int getPositionOfFirstCommitment() {
        return positionOfFirstCommitment;
    }

    public int getPositionOfSecondCommitment() {
        return positionOfSecondCommitment;
    }

    public Zp getZp() {
        return zp;
    }

    public PredicateTypePrimitive getType() {
        return type;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EqualityPublicParameters that = (EqualityPublicParameters) o;
        return positionOfFirstCommitment == that.positionOfFirstCommitment &&
                positionOfSecondCommitment == that.positionOfSecondCommitment &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(g1, that.g1) &&
                Objects.equals(h, that.h) &&
                Objects.equals(commitment, that.commitment) &&
                Objects.equals(group1, that.group1) &&
                type == that.type;
    }

    @Override
    public int hashCode() {
        return Objects.hash(zp, g1, h, commitment, group1, positionOfFirstCommitment, positionOfSecondCommitment, type);
    }
}
