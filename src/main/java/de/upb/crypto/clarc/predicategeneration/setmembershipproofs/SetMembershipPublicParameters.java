package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorIdentity;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedSet;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;
import java.util.Set;

/**
 * Public parameter object containing all relevant information to execute a SetMembership proof
 */
public class SetMembershipPublicParameters implements PredicatePublicParameters {

    @UniqueByteRepresented
    @RepresentedSet(elementRestorer = @Represented)
    private Set<NguyenAccumulatorIdentity> setMembers;

    @Represented
    private Zp zp;

    @UniqueByteRepresented
    @Represented(structure = "groupPrime", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g2, h, commitment;
    @Represented
    private Group groupPrime;

    @UniqueByteRepresented
    @Represented
    private NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters;

    @UniqueByteRepresented
    @Represented
    private int positionOfCommitment;

    /**
     * @param g2                                The generator used in the commitment for the randomness
     * @param h                                 The generator used in the commitment for the Zp representation of alpha
     * @param commitment                        commitment value C for the first commitment on alpha1
     * @param setMembers                        the set of values the committed value needs to be a member
     * @param positionOfCommitment              position of alpha in the credential / attribute space
     * @param nguyenAccumulatorPublicParameters the public parameter of the nguyen accumulator, computed by the
     *                                          verifier
     * @param zp                                Zp used in the system
     */
    public SetMembershipPublicParameters(GroupElement g2, GroupElement h, GroupElement commitment,
                                         Set<NguyenAccumulatorIdentity> setMembers, int positionOfCommitment,
                                         NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                         Zp zp) {
        this.g2 = g2;
        this.h = h;
        this.commitment = commitment;
        this.groupPrime = g2.getStructure();
        this.setMembers = setMembers;
        this.positionOfCommitment = positionOfCommitment;
        this.nguyenAccumulatorPublicParameters = nguyenAccumulatorPublicParameters;
        this.zp = zp;
    }

    /**
     * Constructor used when the verifier does not know the commitment
     *
     * @param g2                                The generator used in the commitment for the randomness
     * @param h                                 The generator used in the commitment for the Zp representation of alpha
     * @param setMembers                        the set of values the committed value needs to be a member
     * @param positionOfCommitment              position of alpha in the credential / attribute space
     * @param nguyenAccumulatorPublicParameters the public parameter of the nguyen accumulator, computed by the
     *                                          verifier
     * @param zp                                Zp used in the system
     */
    public SetMembershipPublicParameters(GroupElement g2, GroupElement h, Set<NguyenAccumulatorIdentity> setMembers,
                                         int positionOfCommitment,
                                         NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                         Zp zp) {
        this.g2 = g2;
        this.h = h;
        this.groupPrime = g2.getStructure();
        this.setMembers = setMembers;
        this.positionOfCommitment = positionOfCommitment;
        this.nguyenAccumulatorPublicParameters = nguyenAccumulatorPublicParameters;
        this.zp = zp;
    }

    public SetMembershipPublicParameters(Representation representation) {
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

    public GroupElement getH() {
        return h;
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

    public int getPositionOfCommitment() {
        return positionOfCommitment;
    }

    public Set<NguyenAccumulatorIdentity> getSetMembers() {
        return setMembers;
    }

    public NguyenAccumulatorPublicParameters getNguyenAccumulatorPublicParameters() {
        return nguyenAccumulatorPublicParameters;
    }

    public Zp getZp() {
        return zp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SetMembershipPublicParameters that = (SetMembershipPublicParameters) o;
        return getPositionOfCommitment() == that.getPositionOfCommitment() &&
                Objects.equals(getSetMembers(), that.getSetMembers()) &&
                Objects.equals(getZp(), that.getZp()) &&
                Objects.equals(getG2(), that.getG2()) &&
                Objects.equals(getH(), that.getH()) &&
                Objects.equals(getCommitment(), that.getCommitment()) &&
                Objects.equals(groupPrime, that.groupPrime) &&
                Objects
                        .equals(getNguyenAccumulatorPublicParameters(), that.getNguyenAccumulatorPublicParameters());
    }

    @Override
    public int hashCode() {
        return Objects
                .hash(getSetMembers(), getZp(), getG2(), getH(), getCommitment(), groupPrime,
                        getNguyenAccumulatorPublicParameters(), getPositionOfCommitment());
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
