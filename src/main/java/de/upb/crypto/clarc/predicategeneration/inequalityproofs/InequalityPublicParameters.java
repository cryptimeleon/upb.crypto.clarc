package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

public class InequalityPublicParameters implements PredicatePublicParameters {
    @Represented
    private Zp zp;

    @UniqueByteRepresented
    @Represented(structure = "group1", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g1, h, commitment;

    @Represented
    private Group group1;

    @UniqueByteRepresented
    @Represented(structure = "group2", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g2, y;

    @Represented
    private Group group2;

    @UniqueByteRepresented
    @Represented
    private int positionOfFirstCommitment, positionOfSecondCommitment;

    /**
     * Constructor for a prover for a type 3 inequality proof
     *
     * @param g1                         The generator used in the commitment for the randomness
     * @param h                          The generator used in the commitment for the Zp representation of alpha
     * @param commitment                 commitment value C for the commitment
     * @param g2                         the second generator, used to compute the predefined value y, that the
     *                                   commitment needs to be unequal to
     * @param y                          the predefined value, the commitment c is proven to be unequal to
     * @param positionOfFirstCommitment  position of alpha 1 in the credential / attribute space
     * @param positionOfSecondCommitment position of alpha 2 in the credential / attribute space, if a type 3 proof
     *                                   is executed
     * @param zp                         Zp used in the system
     */
    public InequalityPublicParameters(GroupElement g1, GroupElement h, GroupElement commitment, GroupElement g2,
                                      GroupElement y, int positionOfFirstCommitment, int positionOfSecondCommitment,
                                      Zp zp) {
        this.g1 = g1;
        this.h = h;
        this.commitment = commitment;
        this.group1 = g1.getStructure();
        this.g2 = g2;
        this.y = y;
        this.group2 = g2.getStructure();
        this.positionOfFirstCommitment = positionOfFirstCommitment;
        this.positionOfSecondCommitment = positionOfSecondCommitment;
        this.zp = zp;

    }


    /**
     * Constructor for a prover for a type 3 inequality proof
     *
     * @param g1                         The generator used in the commitment for the randomness
     * @param h                          The generator used in the commitment for the Zp representation of alpha
     * @param g2                         the second generator, used to compute the predefined value y, that the
     *                                   commitment needs to be unequal to
     * @param y                          the predefined value, the commitment c is proven to be unequal to
     * @param positionOfFirstCommitment  position of alpha 1 in the credential / attribute space
     * @param positionOfSecondCommitment position of alpha 2 in the credential / attribute space, if a type 3 proof
     *                                   is executed
     * @param zp                         Zp used in the system
     */
    public InequalityPublicParameters(GroupElement g1, GroupElement h, GroupElement g2,
                                      GroupElement y, int positionOfFirstCommitment, int positionOfSecondCommitment,
                                      Zp zp) {
        this(g1, h, null, g2, y, positionOfFirstCommitment, positionOfSecondCommitment, zp);
    }


    /**
     * Constructor for a prover for a type 1 or type 2 inequality proof
     *
     * @param g1                        The generator used in the commitment for the randomness
     * @param h                         The generator used in the commitment for the Zp representation of alpha
     * @param commitment                commitment value C for the first commitment on alpha1
     * @param g2                        the second generator, used to compute the predefined value y, that the
     *                                  commitment needs to be unequal to
     * @param y                         the predefined value, the commitment c is proven to be unequal to
     * @param positionOfFirstCommitment position of alpha 1 in the credential / attribute space
     * @param zp                        Zp used in the system
     */
    public InequalityPublicParameters(GroupElement g1, GroupElement h, GroupElement commitment, GroupElement g2,
                                      GroupElement y, int positionOfFirstCommitment,
                                      Zp zp) {
        this(g1, h, commitment, g2, y, positionOfFirstCommitment, -1, zp);
    }

    /**
     * Constructor for a verifier for a type 1 or 2 inequality proof.
     * Since the commitments are not generated yet, this value is set to the neutral element of the group
     *
     * @param g1                        The generator used in the commitment for the randomness
     * @param h                         The generator used in the commitment for the Zp representation of alpha
     * @param g2                        the second generator, used to compute the predefined value y, that the
     *                                  commitment needs to be unequal to
     * @param y                         the predefined value, the commitment c is proven to be unequal to
     * @param positionOfFirstCommitment position of alpha 1 in the credential / attribute space
     * @param zp                        Zp used in the system
     */
    public InequalityPublicParameters(GroupElement g1, GroupElement h, GroupElement g2,
                                      GroupElement y, int positionOfFirstCommitment, Zp zp) {
        this(g1, h, g1.getStructure().getNeutralElement(), g2, y, positionOfFirstCommitment, -1, zp);
    }

    public InequalityPublicParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    public GroupElement getG1() {
        return g1;
    }

    public void setG1(GroupElement g1) {
        this.g1 = g1;
    }

    public GroupElement getH() {
        return h;
    }

    public void setH(GroupElement h) {
        this.h = h;
    }

    public GroupElement getCommitment() {
        return commitment;
    }

    public void setCommitment(GroupElement commitment) {
        this.commitment = commitment;
    }

    public GroupElement getG2() {
        return g2;
    }

    public void setG2(GroupElement g2) {
        this.g2 = g2;
    }

    public GroupElement getY() {
        return y;
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

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        InequalityPublicParameters that = (InequalityPublicParameters) o;
        return positionOfFirstCommitment == that.positionOfFirstCommitment &&
                positionOfSecondCommitment == that.positionOfSecondCommitment &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(g1, that.g1) &&
                Objects.equals(h, that.h) &&
                Objects.equals(commitment, that.commitment) &&
                Objects.equals(group1, that.group1) &&
                Objects.equals(g2, that.g2) &&
                Objects.equals(y, that.y) &&
                Objects.equals(group2, that.group2);
    }

    @Override
    public int hashCode() {
        return Objects.hash(zp, g1, h, commitment, group1, g2, y, group2,
                positionOfFirstCommitment, positionOfSecondCommitment);
    }
}
