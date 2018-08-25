package de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof;

import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class ZeroToUPowLRangeProofProtocolFactory {

    private ZeroToUPowLRangeProofPublicParameters rangePP;
    private String uniqueName;

    /**
     * Constructor for a verifier, if he knows the commitment values
     *
     * @param commitmentOnAttribute to proof that the value is in the set
     * @param pedersenPP            used to generate the commitment on the attributes
     * @param base                  of the upper bound of the range
     * @param exponent              of the upper bound of the range
     * @param positionOfCommitment  position of the attribute in the credential / attribute space
     * @param zp                    Zp used in the system
     * @param accumulatorPP         public parameters of the accumulator used by the system
     * @param uniqueName            unique name for the protocol
     */
    public ZeroToUPowLRangeProofProtocolFactory(PedersenCommitmentValue commitmentOnAttribute,
                                                PedersenPublicParameters pedersenPP, BigInteger base,
                                                int exponent, int positionOfCommitment, Zp zp,
                                                NguyenAccumulatorPublicParameters accumulatorPP,
                                                String uniqueName) {
        GroupElement h = pedersenPP.getH()[0];
        GroupElement g2 = pedersenPP.getG();

        // Verify given base against public Nguyen accumulator parameters
        if (base.compareTo(accumulatorPP.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The base is invalid and does not match the" +
                    " precomputed NguyenAccumulator");
        }

        this.rangePP = new ZeroToUPowLRangeProofPublicParameters(g2, h, commitmentOnAttribute.getCommitmentElement(),
                base, exponent, positionOfCommitment, accumulatorPP, zp);

        this.uniqueName = uniqueName;
    }

    /**
     * Constructor for a verifier, if he does not knows the commitment values
     *
     * @param base                 of the upper bound of the range
     * @param pedersenPP           used to generate the commitment on the attributes
     * @param base                 of the upper bound of the range
     * @param exponent             of the upper bound of the range
     * @param positionOfCommitment position of the attribute in the credential / attribute space
     * @param zp                   Zp used in the system
     * @param accumulatorPP        public parameters of the accumulator used by the system
     * @param uniqueName           unique name for the protocol
     */
    public ZeroToUPowLRangeProofProtocolFactory(PedersenPublicParameters pedersenPP, BigInteger base,
                                                int exponent, int positionOfCommitment, Zp zp,
                                                NguyenAccumulatorPublicParameters accumulatorPP,
                                                String uniqueName) {
        this(null, pedersenPP, base, exponent, positionOfCommitment, zp, accumulatorPP, uniqueName);
    }

    /**
     * Constructor usable, if the {@link ZeroToUPowLRangeProofPublicParameters } are already computed.
     * Especially the prover will use this constructor
     *
     * @param rangePP    Fully specified {@link ZeroToUPowLRangeProofPublicParameters}
     * @param uniqueName unique name for the protocol
     */
    public ZeroToUPowLRangeProofProtocolFactory(ZeroToUPowLRangeProofPublicParameters rangePP, String uniqueName) {
        this.rangePP = rangePP;
        this.uniqueName = uniqueName;
    }

    /**
     * returns a prover protocol for an rangeProofProtocol.
     *
     * @param randomValue             for the attribute
     * @param zpRepresentationOfAlpha used to proof unequally to
     * @param v                       the computed accumulator value (given for efficiency reasons)
     * @return a prover protocol.
     */
    public ZeroToUPowLRangeProofProtocol getProverProtocol(Zp.ZpElement randomValue, Zp.ZpElement
            zpRepresentationOfAlpha, NguyenAccumulatorValue v) {
        return new ZeroToUPowLRangeProofProtocol(rangePP, uniqueName, new RangeProofWitness(uniqueName, zpRepresentationOfAlpha, randomValue));
    }

    /**
     * @param v accumulator value, given for efficiency reasons
     * @return a verifier protocol for an rangeProof.
     */
    public ZeroToUPowLRangeProofProtocol getVerifierProtocol(
            NguyenAccumulatorValue v) {
        return new ZeroToUPowLRangeProofProtocol(rangePP, uniqueName, null);
    }

}