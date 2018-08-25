package de.upb.crypto.clarc.predicategeneration.setmembershipproofs;

import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorIdentity;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.Set;

public class SetMembershipProtocolFactory {

    private SetMembershipPublicParameters setPP;
    private String uniqueName;

    /**
     * Constructor for the verifier, in case he knows the commitment already
     * <p>
     * Create a proof for \alpha \in {setMembers} where  alpha is the value inside the commitment.
     *
     * @param commitmentOnAttribute to proof that the value is in the set
     * @param pedersenPP            used to generate the commitment on the attributes
     * @param setMembers            the set of values, the value inside the given commitment is part of.
     * @param positionOfCommitment  position of the attribute in the credential / attribute space
     * @param zp                    Zp used in the system
     * @param ppNguyen              public parameters of the accumulator used in the system
     * @param uniqueName            unique name for the protocol
     */
    public SetMembershipProtocolFactory(PedersenCommitmentValue commitmentOnAttribute,
                                        PedersenPublicParameters pedersenPP, Set<Zp.ZpElement> setMembers,
                                        int positionOfCommitment, Zp zp, NguyenAccumulatorPublicParameters ppNguyen,
                                        String uniqueName) {
        GroupElement g2 = pedersenPP.getG();
        GroupElement h = pedersenPP.getH()[0];
        GroupElement commitment = commitmentOnAttribute.getCommitmentElement();

        // Use Nguyen Accumulator from PP
        if (BigInteger.valueOf(setMembers.size()).compareTo(ppNguyen.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The set is to large for the precomputed NguyenPP." +
                    "Please split the set in several matching sets of size <="
                    + ppNguyen.getUpperBoundForAccumulatableIdentities().toString() + " and combine them with PoPK");
        }

        //Transform the set to a  Set<NguyenAccumulatorIdentity>
        Set<NguyenAccumulatorIdentity> members = new LinkedHashSet<>();
        for (Zp.ZpElement setMember : setMembers) {
            members.add(new NguyenAccumulatorIdentity(setMember));
        }
        setPP = new SetMembershipPublicParameters(g2, h, commitment, members, positionOfCommitment, ppNguyen, zp);
        this.uniqueName = uniqueName;
    }

    /**
     * Constructor for the verifier, because he does not know the commitment (set later on)
     * <p>
     * Create a proof for \alpha \in {setMembers} where  alpha is the value inside the commitment.
     *
     * @param pedersenPP           used to generate the commitment on the attributes
     * @param setMembers           the set of values, the value inside the given commitment is part of.
     * @param positionOfCommitment position of the attribute in the credential / attribute space
     * @param zp                   Zp used in the system
     * @param ppNguyen             public parameters of the accumulator used in the system
     * @param uniqueName           unique name for the protocol
     */
    public SetMembershipProtocolFactory(PedersenPublicParameters pedersenPP, Set<Zp.ZpElement> setMembers,
                                        int positionOfCommitment, Zp zp, NguyenAccumulatorPublicParameters ppNguyen,
                                        String uniqueName) {
        GroupElement g2 = pedersenPP.getG();
        GroupElement h = pedersenPP.getH()[0];

        // Use Nguyen Accumulator from PP
        if (BigInteger.valueOf(setMembers.size()).compareTo(ppNguyen.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The set is to large for the precomputed NguyenPP." +
                    "Please split the set in several matching sets of size <="
                    + ppNguyen.getUpperBoundForAccumulatableIdentities().toString() + " and combine them with PoPK");
        }

        //Transform the set to a  Set<NguyenAccumulatorIdentity>
        Set<NguyenAccumulatorIdentity> members = new LinkedHashSet<>();
        for (Zp.ZpElement setMember : setMembers) {
            members.add(new NguyenAccumulatorIdentity(setMember));
        }
        setPP = new SetMembershipPublicParameters(g2, h, members, positionOfCommitment, ppNguyen, zp);
        this.uniqueName = uniqueName;
    }

    /**
     * Constructor for the prover, if the {@link SetMembershipPublicParameters } are already computed (by the verifier)
     *
     * @param setPP      Fully specified {@link SetMembershipPublicParameters}
     * @param uniqueName unique name for the protocol
     */
    public SetMembershipProtocolFactory(SetMembershipPublicParameters setPP, String uniqueName) {
        this.setPP = setPP;
        this.uniqueName = uniqueName;
    }

    /**
     * returns a prover protocol for an setMembership proof.
     *
     * @param commitmentPair          for the attribute
     * @param zpRepresentationOfAlpha used to proof unequally to
     * @return a prover protocol.
     */
    public SetMembershipProofProtocol getProverProtocol(PedersenCommitmentPair commitmentPair, Zp.ZpElement
            zpRepresentationOfAlpha) {
        return new SetMembershipProofProtocol(commitmentPair.getOpenValue().getRandomValue(), zpRepresentationOfAlpha,
                setPP, uniqueName);
    }

    /**
     * @return a verifier protocol for an set membership proof.
     */
    public SetMembershipProofProtocol getVerifierProtocol() {
        return new SetMembershipProofProtocol(setPP, uniqueName);
    }
}
