package de.upb.crypto.clarc.predicategeneration.parametergeneration;

import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProofProtocol;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorIdentity;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.LinkedHashSet;
import java.util.Set;

public class SetMembershipParameterGen {

    /**
     * Generate {@link SetMembershipPublicParameters} to create an instance of {@link SetMembershipProofProtocol}
     * to prove set membership of a committed value to a given set of public values.
     *
     * @param pedersenPP           commitment scheme used in the system
     * @param positionInCredential position in space / credential
     * @param setMembers           set of values for which it shall be proven that the committed
     *                             value is equal to one of them.
     * @param ppNguyen             pp of the Nguyen Accumulator of the system
     * @return parameters to create {@link SetMembershipProofProtocol} to prove set membership of a committed value
     * to the given public values
     */
    public static SetMembershipPublicParameters createSetMembershipPP(PedersenPublicParameters pedersenPP,
                                                                      int positionInCredential,
                                                                      Set<Zp.ZpElement> setMembers,
                                                                      NguyenAccumulatorPublicParameters ppNguyen,
                                                                      Zp zp) {

        GroupElement h = pedersenPP.getH()[0];
        GroupElement g2 = pedersenPP.getG();

        // Use Nguyen Accumulator from PP
        if (BigInteger.valueOf(setMembers.size()).compareTo(ppNguyen.getUpperBoundForAccumulatableIdentities()) >= 0) {
            throw new IllegalArgumentException("The set is to large for the precomputed NguyenPP." +
                    "Please split the set in several matching sets of size <=" +
                    ppNguyen.getUpperBoundForAccumulatableIdentities().toString() +
                    " and combine them with PoPK");
        }

        // Transform the set to a  Set<NguyenAccumulatorIdentity>
        Set<NguyenAccumulatorIdentity> members = new LinkedHashSet<>();
//        Set<Zp.ZpElement> zpReprOfSetmembers = setMembers.stream().map(pair -> pair.getZpRepresentation(hashIntoZp))
//                                                         .collect(Collectors.toSet());
        for (Zp.ZpElement setMember : setMembers) {
            members.add(new NguyenAccumulatorIdentity(setMember));
        }
        return new SetMembershipPublicParameters(g2, h, members, positionInCredential, ppNguyen, zp);
    }
}
