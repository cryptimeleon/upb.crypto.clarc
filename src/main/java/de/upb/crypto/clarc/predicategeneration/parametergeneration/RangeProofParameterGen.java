package de.upb.crypto.clarc.predicategeneration.parametergeneration;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class RangeProofParameterGen {

    /**
     * Generate {@link ArbitraryRangeProofPublicParameters} to create an instance of
     * {@link ArbitraryRangeProofProtocol} to prove that the committed value is within a range.
     *
     * @param pedersenPP           used to generate the commitment on the attributes
     * @param lowerBound           of the range
     * @param upperBound           of the range
     * @param positionOfCommitment position of the attribute in the credential / attribute space
     * @param zp                   Zp used in the system
     * @param accumulatorPP        public parameters of the accumulator used for the system
     * @return the range PP without a commitment set
     */
    @Deprecated
    public static ArbitraryRangeProofPublicParameters getRangePP(PedersenPublicParameters pedersenPP,
                                                                 BigInteger lowerBound,
                                                                 BigInteger upperBound, int positionOfCommitment,
                                                                 Zp zp,
                                                                 NguyenAccumulatorPublicParameters accumulatorPP) {
        GroupElement h = pedersenPP.getH()[0];
        GroupElement g2 = pedersenPP.getG();

        // Compute matching u = base and l=exponent, s,t,  0 < B - A  < min(p+1/2u-1, u^l-1)
        // start with u =2 and compute l = log_u( B) (sealed) and if this does not fulfill the requirement stops
        // iteration
        BigInteger base = getBase(lowerBound, upperBound);
        BigInteger p = zp.size();
        int exponent;

        // Iteratively compute l, s.t. B - A < u^l
        exponent = 0;
        // While B -A >= u^l-1
        while (upperBound.subtract(lowerBound).compareTo(base.pow(exponent).subtract(BigInteger.ONE)) >= 0) {
            exponent++;
        }

        validateParameters(base, exponent, upperBound, lowerBound, p);

        // Verify given base against public Nguyen accumulator parameters
        if (base.compareTo(accumulatorPP.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The base is invalid and does not match the" +
                    " precomputed NguyenAccumulator");
        }

        return new ArbitraryRangeProofPublicParameters(g2, h, base, exponent,
                positionOfCommitment, accumulatorPP, zp, lowerBound, upperBound);
    }

    public static ArbitraryRangeProofPublicParameters getRangePP(PedersenPublicParameters pedersenPP,
                                                                 GroupElement commitment,
                                                                 BigInteger lowerBound,
                                                                 BigInteger upperBound, int positionOfCommitment,
                                                                 Zp zp,
                                                                 NguyenAccumulatorPublicParameters accumulatorPP) {
        GroupElement h = pedersenPP.getH()[0];
        GroupElement g2 = pedersenPP.getG();

        // Compute matching u = base and l=exponent, s,t,  0 < B - A  < min(p+1/2u-1, u^l-1)
        // start with u =2 and compute l = log_u( B) (sealed) and if this does not fulfill the requirement stops
        // iteration
        BigInteger base = getBase(lowerBound, upperBound);
        BigInteger p = zp.size();
        int exponent;

        // Iteratively compute l, s.t. B - A < u^l
        exponent = 0;
        // While B -A >= u^l-1
        while (upperBound.subtract(lowerBound).compareTo(base.pow(exponent).subtract(BigInteger.ONE)) >= 0) {
            exponent++;
        }

        validateParameters(base, exponent, upperBound, lowerBound, p);

        // Verify given base against public Nguyen accumulator parameters
        if (base.compareTo(accumulatorPP.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The base is invalid and does not match the" +
                    " precomputed NguyenAccumulator");
        }

        return new ArbitraryRangeProofPublicParameters(g2, h, commitment, base, exponent,
                positionOfCommitment, accumulatorPP, zp, lowerBound, upperBound);
    }

    private static void validateParameters(BigInteger base, int exponent, BigInteger upperBound,
                                           BigInteger lowerBound, BigInteger p) {
        // Check if B - A > 0
        if (upperBound.subtract(lowerBound).compareTo(BigInteger.valueOf(0)) <= 0) {
            throw new IllegalArgumentException("Invalid Parameter, upper bound needs to be greater than lower bound");
        }
        // Check if B - A  < CompBound = p+1 / 2u -1
        BigInteger compBound =
                p.add(BigInteger.ONE).divide(BigInteger.valueOf(2).multiply(base).add(BigInteger.ONE));
        if (upperBound.subtract(lowerBound).compareTo(compBound) >= 0) {
            throw new IllegalArgumentException("Cannot represent this Range!");
        }
        // Check if u^l - 1 < p
        if (base.pow(exponent).subtract(BigInteger.ONE).compareTo(p) >= 0) {
            throw new IllegalArgumentException("Cannot represent this Range using the given range!");
        }
    }

    /**
     * Currently, only 2 is used as a base. If a more efficient numeric computation of the base is desired, one can
     * simply put this in here
     *
     * @param lowerBound of the interval
     * @param upperBound of the interval
     * @return a base for the representation of the interval
     */
    private static BigInteger getBase(BigInteger lowerBound, BigInteger upperBound) {
        return BigInteger.valueOf(16);
    }
}
