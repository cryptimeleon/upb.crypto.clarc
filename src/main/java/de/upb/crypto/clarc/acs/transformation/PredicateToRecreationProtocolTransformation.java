package de.upb.crypto.clarc.acs.transformation;

import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolPublicParameters;
import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrPublicParameter;
import de.upb.crypto.clarc.protocols.parameters.EmptyProblem;
import de.upb.crypto.clarc.protocols.parameters.Problem;
import de.upb.crypto.craco.interfaces.PublicParameters;

/**
 * This class provides static helper methods to uses the information available in a
 * {@link PredicatePolicyFact} to build a corresponding {@link SigmaProtocol} instance for the contained
 * {@link PredicateTypePrimitive} and {@link PredicatePublicParameters}.
 */
public class PredicateToRecreationProtocolTransformation {
    public static SigmaProtocol transform(PredicatePolicyFact childPolicy,
                                          SubPolicyProvingProtocolPublicParameters p0pp, int position) {
        switch (childPolicy.getProofType()) {
            case EQUALITY_DLOG:
            case EQUALITY_PUBLIC_VALUE:
            case EQUALITY_2_ATTRIBUTES:
                return new GeneralizedSchnorrProtocol(new Problem[]{new EmptyProblem()},
                        null,
                        GeneralizedSchnorrPublicParameter
                                .createEmptyParameters(p0pp.getZp()));
            case INEQUALITY_DLOG:
            case INEQUALITY_PUBLIC_VALUE:
            case INEQUALITY_2_ATTRIBUTES:
                return getInequalityRecreationProtocol(childPolicy.getPublicParameters(), p0pp, position);
            case SET_MEMBERSHIP_ATTRIBUTE:
                return getSetMemebership(childPolicy.getPublicParameters(), p0pp, position);
            case ATTRIBUTE_IN_RANGE:
                return retRange(childPolicy.getPublicParameters(), p0pp, position);
            default:
                throw new IllegalArgumentException("Element must be contained in enum, "
                        + childPolicy.getProofType().toString() + "is not contained");
        }
    }


    private static SigmaProtocol getInequalityRecreationProtocol(PublicParameters predicatePP,
                                                                 SubPolicyProvingProtocolPublicParameters p0pp,
                                                                 int position) {
        if (!InequalityPublicParameters.class.isAssignableFrom(predicatePP.getClass())) {
            throw new IllegalArgumentException("The given public parameters for the protocol do not match");
        }
        InequalityPublicParameters pp = (InequalityPublicParameters) predicatePP;
        InequalityProtocolFactory factory = new InequalityProtocolFactory(pp, "");
        // Ok, since the factory does "Handle" the issue of not existence for the value of w
        return factory.getVerifierProtocol();

    }

    private static SigmaProtocol getSetMemebership(PublicParameters predicatePP,
                                                   SubPolicyProvingProtocolPublicParameters p0pp, int position) {
        if (!SetMembershipPublicParameters.class.isAssignableFrom(predicatePP.getClass())) {
            throw new IllegalArgumentException("The given public parameters for the protocol do not match");
        }
        SetMembershipPublicParameters pp = (SetMembershipPublicParameters) predicatePP;
        SetMembershipProtocolFactory factory = new SetMembershipProtocolFactory(pp, "");
        // Ok, since the factory does "Handle" the issue of not existence for the value of w
        return factory.getVerifierProtocol();
    }

    private static SigmaProtocol retRange(PublicParameters predicatePP, SubPolicyProvingProtocolPublicParameters p0pp,
                                          int position) {
        if (!(predicatePP instanceof ArbitraryRangeProofPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol do not match");
        }
        ArbitraryRangeProofPublicParameters pp = (ArbitraryRangeProofPublicParameters) predicatePP;
        ArbitraryRangeProofProtocolFactory factory = new ArbitraryRangeProofProtocolFactory(pp, "");
        // Ok, since the factory does "Handle" the issue of not existence for the value of w
        return factory.getVerifierProtocol();
    }

}
