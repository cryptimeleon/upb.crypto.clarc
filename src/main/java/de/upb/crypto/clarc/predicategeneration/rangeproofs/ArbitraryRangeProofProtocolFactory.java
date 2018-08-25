package de.upb.crypto.clarc.predicategeneration.rangeproofs;

import de.upb.crypto.clarc.predicategeneration.parametergeneration.RangeProofParameterGen;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.RangeProofWitness;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;

public class ArbitraryRangeProofProtocolFactory {

    private ArbitraryRangeProofPublicParameters rangePP;
    private String uniqueName;

    /**
     * Constructor for a verifier
     *
     * @param commitmentOnAttribute to proof that the value is in the set
     * @param pedersenPP            used to generate the commitment on the attributes
     * @param lowerBound            of the range
     * @param upperBound            of the range
     * @param positionOfCommitment  position of the attribute in the credential / attribute space
     * @param zp                    Zp used in the system
     * @param accumulatorPP         public parameters of the accumulator used for the system
     * @param uniqueName            unique name for the protocol
     */
    public ArbitraryRangeProofProtocolFactory(PedersenCommitmentValue commitmentOnAttribute, PedersenPublicParameters
            pedersenPP, BigInteger lowerBound, BigInteger upperBound, int positionOfCommitment,
                                              Zp zp, NguyenAccumulatorPublicParameters accumulatorPP,
                                              String uniqueName) {
        this.rangePP = RangeProofParameterGen.getRangePP(pedersenPP, commitmentOnAttribute.getCommitmentElement(),
                lowerBound, upperBound, positionOfCommitment, zp, accumulatorPP);
        this.uniqueName = uniqueName;
    }

    /**
     * Constructor usable, if the {@link ArbitraryRangeProofPublicParameters } are already computed.
     * Especially the prover will use this constructor
     *
     * @param rangePP    Fully specified {@link ArbitraryRangeProofPublicParameters}
     * @param uniqueName unique name for the protocol
     */
    public ArbitraryRangeProofProtocolFactory(ArbitraryRangeProofPublicParameters rangePP, String uniqueName) {
        this.rangePP = rangePP;
        this.uniqueName = uniqueName;
    }

    /**
     * returns a prover protocol for an rangeProofProtocol.
     *
     * @param commitmentPair          for the attribute
     * @param zpRepresentationOfAlpha used to proof unequally to
     * @return a prover protocol.
     */
    public ArbitraryRangeProofProtocol getProverProtocol(PedersenCommitmentPair commitmentPair,
                                                         Zp.ZpElement zpRepresentationOfAlpha) {
        return new ArbitraryRangeProofProtocol(new ArbitraryRangeProofPublicParameters(rangePP, commitmentPair.getCommitmentValue().getCommitmentElement()),
                new RangeProofWitness(uniqueName, zpRepresentationOfAlpha, commitmentPair.getOpenValue().getRandomValue()),
                uniqueName);
    }

    /**
     * @return a verifier protocol for an rangeProof.
     */
    public ArbitraryRangeProofProtocol getVerifierProtocol() {
        return new ArbitraryRangeProofProtocol(rangePP, null, uniqueName);
    }
}
