package de.upb.crypto.clarc.predicategeneration.inequalityproofs;

import de.upb.crypto.craco.commitment.interfaces.CommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class InequalityProtocolFactory {

    private InequalityPublicParameters ipp;
    private String uniqueName;
    //this value is only used to determine if the proof is for type 3 or not
    boolean isType3 = false;


    /**
     * Constructor for a type 1 inequality (Section 5.2.1), where s is not publicly known
     * <p>
     * Create a proof for generator^alpha =/= generator ^unequalDLog,
     * where  alpha is the value inside the commitment.
     *
     * @param commitmentOnAttribute     to proof that the value is unequal
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param unequalHiddenValue        the value, for that it needs to be shown that it is unequal to the value. It is
     *                                  hidden, since only the group element unequalHiddenValue is given, where
     *                                  unequalHiddenValue = generator^s for a hidden value s
     *                                  committed on
     * @param generator                 used for the proof of committedValue unequal to unequalDLog
     * @param positionOfFirstCommitment in the attribute space / credential
     * @param zp                        Zp used in the system
     * @param uniqueName                unique name for the protocol
     */
    public InequalityProtocolFactory(PedersenCommitmentValue commitmentOnAttribute, PedersenPublicParameters
            pedersenPP, GroupElement unequalHiddenValue, GroupElement generator, int positionOfFirstCommitment,
                                     Zp zp, String uniqueName) {
        GroupElement g1 = pedersenPP.getG();
        GroupElement h = pedersenPP.getH()[0];
        GroupElement commitment = commitmentOnAttribute.getCommitmentElement();
        ipp = new InequalityPublicParameters(g1, h, commitment, generator, unequalHiddenValue,
                positionOfFirstCommitment, zp);
        this.uniqueName = uniqueName;
    }


    /**
     * Constructor for an arbitrary type, if the {@link InequalityPublicParameters } are already computed.
     *
     * @param ipp        Fully specified {@link InequalityPublicParameters}
     * @param uniqueName unique name for the protocol
     */
    public InequalityProtocolFactory(InequalityPublicParameters ipp, String uniqueName) {
        this.ipp = ipp;
        this.uniqueName = uniqueName;
    }

    /**
     * Constructor for a type 2 inequality (Section 5.2.), where s is publicly known
     * <p>
     * Create a proof for generator^alpha =/= generator ^unequalDLog,
     * where  alpha is the value inside the commitment.
     *
     * @param commitmentOnAttribute     to proof that the value is unequal
     * @param pedersenPP                used to generate the commitment on the attributes
     * @param unequalDLog               the value, for that it needs to be shown that it is unequal to the value
     *                                  committed on
     * @param generator                 used for the proof of committedValue unequal to unequalDLog
     * @param positionOfFirstCommitment the position of the first commitment
     * @param zp                        Zp used in the system
     * @param uniqueName                unique name for the protocol
     */
    public InequalityProtocolFactory(PedersenCommitmentValue commitmentOnAttribute, PedersenPublicParameters
            pedersenPP, Zp.ZpElement unequalDLog, GroupElement generator, int positionOfFirstCommitment,
                                     Zp zp, String uniqueName) {
        GroupElement g1 = pedersenPP.getG();
        GroupElement h = pedersenPP.getH()[0];
        GroupElement commitment = commitmentOnAttribute.getCommitmentElement();
        GroupElement y = generator.pow(unequalDLog);
        ipp = new InequalityPublicParameters(g1, h, commitment, generator, y, positionOfFirstCommitment,
                zp);
        this.uniqueName = uniqueName;
    }

    /**
     * Constructor for a type 3 inequality (Section 5.2.2), where two {@link CommitmentValue} values are inequal.
     * <p>
     * Create a proof for generator^alpha1 =/= generator^alpha2
     * where alpha1 and alpha2 are {@link PedersenCommitmentValue}.
     *
     * @param commitment1                to proof that the value inside  is unequal to commitment2
     * @param commitment2                to proof that the value inside is unequal to commitment1
     * @param pedersenPP                 used to generate the commitment on the attributes
     * @param generator                  used for the proof of committedValue unequal to unequalDLog
     * @param positionOfFirstCommitment  the position of the first commitment
     * @param positionOfSecondCommitment the position of the second commitment
     * @param zp                         Zp used in the system
     * @param uniqueName                 unique name for the protocol
     */
    public InequalityProtocolFactory(PedersenCommitmentValue commitment1, PedersenCommitmentValue commitment2,
                                     PedersenPublicParameters pedersenPP, GroupElement generator,
                                     int positionOfFirstCommitment, int positionOfSecondCommitment,
                                     Zp zp, String uniqueName) {
        this.isType3 = true;
        GroupElement g1 = pedersenPP.getG();
        GroupElement h = pedersenPP.getH()[0];
        GroupElement commitment = commitment1.getCommitmentElement().op(commitment2.getCommitmentElement().inv());
        GroupElement y = generator.getStructure().getNeutralElement();
        ipp = new InequalityPublicParameters(g1, h, commitment, generator, y, positionOfFirstCommitment,
                positionOfSecondCommitment, zp);
        this.uniqueName = uniqueName;
    }


    /**
     * returns a prover protocol for an inequality proof.
     * Works if
     *
     * @param commitmentPair          for the attribute
     * @param zpRepresentationofAlpha used to proof unequally to
     * @return a prover protocol.
     */
    public InequalityProofProtocol getProverProtocol(PedersenCommitmentPair commitmentPair, Zp.ZpElement
            zpRepresentationofAlpha) {
        if (isType3) {
            throw new IllegalArgumentException("Cannot use this constructor, since inequality of two commitments " +
                    "needs to be proven");
        }
        return new InequalityProofProtocol(commitmentPair.getOpenValue().getRandomValue(), zpRepresentationofAlpha, ipp,
                uniqueName);
    }

    /**
     * Creates a prover protocol for proving inequality of two attributes.
     * Only usable if constructor for construction 5.2.3 is used.
     *
     * @param commitmentPair1          random value used in first commitment
     * @param zpRepresentationofAlpha1 ZP representation value of alpha in first commitment
     * @param commitmentPair2          random value used in second commitment
     * @param zpRepresentationofAlpha2 ZP representation value of alpha in second commitment
     * @return a prover protocol
     */
    public InequalityProofProtocol getProverProtocol(PedersenCommitmentPair commitmentPair1, Zp.ZpElement
            zpRepresentationofAlpha1, PedersenCommitmentPair commitmentPair2, Zp.ZpElement zpRepresentationofAlpha2) {
        if (!isType3) {
            throw new IllegalArgumentException("Cannot use this constructor, since inequality of two commitments " +
                    "needs to be proven");
        }
        Zp.ZpElement r = commitmentPair1.getOpenValue().getRandomValue().add(commitmentPair2.getOpenValue()
                .getRandomValue().neg());
        Zp.ZpElement alpha = zpRepresentationofAlpha1.add(zpRepresentationofAlpha2.neg());
        return new InequalityProofProtocol(r, alpha, ipp, uniqueName);
    }

    /**
     * @return a verifier protocol for an inequality proof.
     */
    public InequalityProofProtocol getVerifierProtocol() {
        return new InequalityProofProtocol(ipp, uniqueName);
    }

}
