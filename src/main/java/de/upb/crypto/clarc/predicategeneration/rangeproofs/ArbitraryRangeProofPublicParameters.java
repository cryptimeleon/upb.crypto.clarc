package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.math.hash.annotations.AnnotatedUbrUtil;
import de.upb.crypto.math.hash.annotations.UniqueByteRepresented;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Objects;

public class ArbitraryRangeProofPublicParameters extends ZeroToUPowLRangeProofPublicParameters {

    @UniqueByteRepresented
    @Represented
    private BigInteger lowerBound, upperBound;

    public ArbitraryRangeProofPublicParameters(Representation representation) {
        super(representation);
        //AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public ArbitraryRangeProofPublicParameters(GroupElement g2, GroupElement h, GroupElement commitment,
                                               BigInteger base, int exponent, int positionOfCommitment,
                                               NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                               Zp zp, BigInteger lowerBound, BigInteger upperBound) {
        super(g2, h, commitment, base, exponent, positionOfCommitment, nguyenAccumulatorPublicParameters, zp);
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
    }

    @Deprecated
    public ArbitraryRangeProofPublicParameters(GroupElement g2, GroupElement h,
                                               BigInteger base, int exponent, int positionOfCommitment,
                                               NguyenAccumulatorPublicParameters nguyenAccumulatorPublicParameters,
                                               Zp zp, BigInteger lowerBound, BigInteger upperBound) {
        super(g2, h, base, exponent, positionOfCommitment, nguyenAccumulatorPublicParameters, zp);
        this.lowerBound = lowerBound;
        this.upperBound = upperBound;
    }

    public ArbitraryRangeProofPublicParameters(ArbitraryRangeProofPublicParameters pp, GroupElement commitment) {
        super(pp, commitment);
        this.lowerBound = pp.lowerBound;
        this.upperBound = pp.upperBound;
    }


    /**
     * The representation of this object. Used for serialization
     *
     * @return a Representation or null if the representedTypeName suffices to instantiate an equal object again
     * @see Representation
     */
    @Override
    public Representation getRepresentation() {
        return super.getRepresentation();
    }

    public BigInteger getLowerBound() {
        return lowerBound;
    }

    public BigInteger getUpperBound() {
        return upperBound;
    }


    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ArbitraryRangeProofPublicParameters that = (ArbitraryRangeProofPublicParameters) o;
        return Objects.equals(lowerBound, that.lowerBound) &&
                Objects.equals(upperBound, that.upperBound);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), lowerBound, upperBound);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator accumulator) {
        return AnnotatedUbrUtil.autoAccumulate(accumulator, this);
    }
}
