package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.*;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedSet;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

public class ZeroToUPowLRangeProofPublicParameters implements PredicatePublicParameters {

    @RepresentedSet(elementRestorer = @Represented)
    private Set<NguyenAccumulatorIdentity> omega;

    @Represented
    private Zp zp;

    @Represented(structure = "groupPrime", recoveryMethod = GroupElement.RECOVERY_METHOD)
    private GroupElement g2, h, commitment;

    @Represented
    private Group groupPrime;

    @Represented
    private BigInteger base;

    @Represented
    private int exponent;

    @Represented
    private NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters;

    @Represented
    private int positionOfCommitment;

    // cache values
    private NguyenAccumulatorValue v;
    private HashMap<NguyenAccumulatorIdentity, NguyenWitness> accumulatorWitnesses;

    public ZeroToUPowLRangeProofPublicParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        initValues();
    }

    /**
     * Constructor for a prover
     * Note that it must hold that:
     * u^l-1 &lt; p and u &lt; = q
     *
     * @param g2                                The generator used in the commitment for the randomness
     * @param h                                 The generator used in the commitment for the Zp representation of alpha
     * @param base                              the value of u
     * @param exponent                          the value of l
     * @param positionOfCommitment              position of alpha in the credential / attribute space
     * @param nguyenAccumulatorPublicParameters the public parameter of the nguyen accumulator, computed by the
     *                                          verifier
     * @param zp                                the Zp group used in the clarcPP
     */
    public ZeroToUPowLRangeProofPublicParameters(GroupElement g2, GroupElement h, GroupElement commitment,
                                                 BigInteger base, int exponent,
                                                 int positionOfCommitment,
                                                 NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                                 Zp zp) {
        this.g2 = g2;
        this.h = h;
        this.commitment = commitment;
        this.groupPrime = g2.getStructure();
        this.base = base;
        this.exponent = exponent;
        this.omega = new HashSet<>();
        this.positionOfCommitment = positionOfCommitment;
        this.nguyenAccumulatorPublicParameters = nguyenAccumulatorPublicParameters;
        this.zp = zp;
        initValues();
    }

    public void setCommitment(GroupElement commitment) {
        this.commitment = commitment;
    }

    @Deprecated
    public ZeroToUPowLRangeProofPublicParameters(GroupElement g2, GroupElement h,
                                                 BigInteger base, int exponent,
                                                 int positionOfCommitment,
                                                 NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                                 Zp zp) {
        this.g2 = g2;
        this.h = h;
        this.groupPrime = g2.getStructure();
        this.base = base;
        this.exponent = exponent;
        this.omega = new HashSet<>();
        this.positionOfCommitment = positionOfCommitment;
        this.nguyenAccumulatorPublicParameters = nguyenAccumulatorPublicParameters;
        this.zp = zp;
        initValues();
    }

    /**
     * Copy constructor, copying data from the original parameters, but with given commitment
     */
    public ZeroToUPowLRangeProofPublicParameters(ZeroToUPowLRangeProofPublicParameters params, GroupElement commitment) {
        this.omega = params.omega;
        this.zp = params.zp;
        this.g2 = params.g2;
        this.h = params.h;
        this.commitment = commitment;
        this.groupPrime = params.groupPrime;
        this.base = params.base;
        this.exponent = params.exponent;
        this.nguyenAccumulatorPublicParameters = params.nguyenAccumulatorPublicParameters;
        this.positionOfCommitment = params.positionOfCommitment;
        this.v = params.v;
        this.accumulatorWitnesses = params.accumulatorWitnesses;
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

    protected void initValues() {
        NguyenAccumulator acc = new NguyenAccumulator(nguyenAccumulatorPublicParameters);

        for (BigInteger i = BigInteger.ZERO; i.compareTo(base) < 0; i = i.add(BigInteger.ONE)) {
            omega.add(new NguyenAccumulatorIdentity(zp.createZnElement(i)));
        }

        this.v = acc.create(omega);

        this.accumulatorWitnesses = new HashMap<>();
        for (NguyenAccumulatorIdentity accumulatedValue : omega) {
            accumulatorWitnesses.put(accumulatedValue, acc.createWitness(omega, accumulatedValue));
        }
    }

    public GroupElement getH() {
        return h;
    }

    public GroupElement getCommitment() {
        return commitment;
    }

    public GroupElement getG2() {
        return g2;
    }

    public BigInteger getBase() {
        return base;
    }

    public int getExponent() {
        return exponent;
    }

    public int getPositionOfCommitment() {
        return positionOfCommitment;
    }

    public Set<NguyenAccumulatorIdentity> getOmega() {
        return omega;
    }

    public NguyenAccumulatorPublicParameters getNguyenAccumulatorPublicParameters() {
        return nguyenAccumulatorPublicParameters;
    }

    public NguyenAccumulatorValue getAccumulatorValue() {
        return v;
    }

    public NguyenWitness getAccumulatorWitness(NguyenAccumulatorIdentity accumulatedValue) {
        if (!omega.contains(accumulatedValue))
            throw new IllegalArgumentException(accumulatedValue.toString() + " is not accumulated");
        return accumulatorWitnesses.get(accumulatedValue);
    }

    public Zp getZp() {
        return zp;
    }

    public void setZp(Zp zp) {
        this.zp = zp;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ZeroToUPowLRangeProofPublicParameters
                that = (ZeroToUPowLRangeProofPublicParameters) o;
        return getPositionOfCommitment() == that.getPositionOfCommitment() &&
                Objects.equals(getOmega(), that.getOmega()) &&
                Objects.equals(getZp(), that.getZp()) &&
                Objects.equals(getG2(), that.getG2()) &&
                Objects.equals(getH(), that.getH()) &&
                Objects.equals(getCommitment(), that.getCommitment()) &&
                Objects.equals(groupPrime, that.groupPrime) &&

                Objects.equals(getBase(), that.getBase()) &&
                Objects.equals(getExponent(), that.getExponent()) &&
                Objects.equals(getNguyenAccumulatorPublicParameters(),
                        that.getNguyenAccumulatorPublicParameters());
    }

    @Override
    public int hashCode() {
        return Objects
                .hash(getOmega(), getZp(), getG2(), getH(), getCommitment(), groupPrime, getBase(),
                        getExponent(), getNguyenAccumulatorPublicParameters(), getPositionOfCommitment());
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        if (g2 != null) { //I believe these are never null!?
            accumulator.escapeAndSeparate(g2);
        } else {
            accumulator.appendSeperator();
        }
        if (h != null) {
            accumulator.escapeAndSeparate(h);
        } else {
            accumulator.appendSeperator();
        }
        if (commitment != null) {
            accumulator.escapeAndSeparate(commitment);
        } else {
            accumulator.appendSeperator();
        }

        accumulator.appendAndSeparate(base.toByteArray());
        accumulator.appendAndSeparate(Integer.toBinaryString(exponent));
        accumulator.escapeAndSeparate(BigInteger.valueOf(positionOfCommitment).toByteArray());
        return accumulator;
    }

}
