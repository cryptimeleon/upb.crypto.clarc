package de.upb.crypto.clarc.acs.transformation;

import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolPublicParameters;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolWitness;
import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.clarc.protocols.parameters.Witness;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.math.interfaces.structures.GroupElement;

/**
 * This class provides static helper methods to uses the information available in a
 * {@link PredicatePolicyFact} to build a corresponding {@link SigmaProtocol} instance for the contained
 * {@link PredicateTypePrimitive} and {@link PredicatePublicParameters}.
 */
public class PredicateToSigmaProtocolTransformation {
    public static SigmaProtocol transform(PredicatePolicyFact childPolicy, Witness pcpWitness,
                                          SubPolicyProvingProtocolPublicParameters subPolPP, int position) {
        switch (childPolicy.getProofType()) {
            case EQUALITY_DLOG:
                return getEqualityDefaultType(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case EQUALITY_PUBLIC_VALUE:
                return getEqualityDefaultType(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case EQUALITY_2_ATTRIBUTES:
                return getEqualityTwoCommitments(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case INEQUALITY_DLOG:
                return getInequalityDefaultType(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case INEQUALITY_PUBLIC_VALUE:
                return getInequalityDefaultType(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case INEQUALITY_2_ATTRIBUTES:
                return getInEqualityTwoCommitments(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case SET_MEMBERSHIP_ATTRIBUTE:
                return getSetMemebership(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            case ATTRIBUTE_IN_RANGE:
                return retRange(childPolicy.getPublicParameters(), pcpWitness, subPolPP, position);
            default:
                throw new IllegalArgumentException("Element must be contained in enum, "
                        + childPolicy.getProofType().toString() + "is not contained");
        }
    }

    private static SigmaProtocol getEqualityDefaultType(PublicParameters predicatePP, Witness witness,
                                                        SubPolicyProvingProtocolPublicParameters subPolPP,
                                                        int position) {
        if (!(predicatePP instanceof EqualityPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        EqualityPublicParameters pp = (EqualityPublicParameters) predicatePP;
        pp.setCommitment(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment())
                .getCommitmentElement());
        EqualityProtocolFactory factory = new EqualityProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(
                    subPolWitness.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfFirstCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }

    private static SigmaProtocol getEqualityTwoCommitments(PublicParameters predicatePP, Witness witness,
                                                           SubPolicyProvingProtocolPublicParameters subPolPP,
                                                           int position) {
        if (!(predicatePP instanceof EqualityPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        EqualityPublicParameters pp = (EqualityPublicParameters) predicatePP;
        if (pp.getPositionOfSecondCommitment() == -1) {
            throw new IllegalArgumentException("The given public parameter are not compatible with this proof type ");
        }
        //Compute com = C1-C2
        GroupElement com = subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment())
                .getCommitmentElement()
                .op(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfSecondCommitment())
                        .getCommitmentElement().inv());
        pp.setCommitment(com);
        EqualityProtocolFactory factory = new EqualityProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(
                    subPolWitness.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment()),
                    subPolWitness.getCommitmentsOnAttributes().get(pp.getPositionOfSecondCommitment()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }

    private static SigmaProtocol getInequalityDefaultType(PublicParameters predicatePP, Witness witness,
                                                          SubPolicyProvingProtocolPublicParameters subPolPP,
                                                          int position) {
        if (!(predicatePP instanceof InequalityPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        InequalityPublicParameters pp = (InequalityPublicParameters) predicatePP;
        pp.setCommitment(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment())
                .getCommitmentElement());
        InequalityProtocolFactory factory = new InequalityProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(
                    subPolWitness.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfFirstCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }

    private static SigmaProtocol getInEqualityTwoCommitments(PublicParameters predicatePP, Witness witness,
                                                             SubPolicyProvingProtocolPublicParameters subPolPP,
                                                             int position) {
        if (!(predicatePP instanceof InequalityPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        InequalityPublicParameters pp = (InequalityPublicParameters) predicatePP;
        if (pp.getPositionOfSecondCommitment() == -1) {
            throw new IllegalArgumentException("The given public parameter are not compatible with this proof type ");
        }
        //Compute com = C1-C2
        GroupElement com = subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfFirstCommitment())
                .getCommitmentElement()
                .op(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfSecondCommitment())
                        .getCommitmentElement().inv());
        pp.setCommitment(com);
        InequalityProtocolFactory factory = new InequalityProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(subPolWitness.getCommitmentsOnAttributes()
                            .get(pp.getPositionOfFirstCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfFirstCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()),
                    subPolWitness.getCommitmentsOnAttributes().get(pp.getPositionOfSecondCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfSecondCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }

    private static SigmaProtocol getSetMemebership(PublicParameters predicatePP, Witness witness,
                                                   SubPolicyProvingProtocolPublicParameters subPolPP, int position) {
        if (!(predicatePP instanceof SetMembershipPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        SetMembershipPublicParameters pp = (SetMembershipPublicParameters) predicatePP;
        pp.setCommitment(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfCommitment())
                .getCommitmentElement());
        SetMembershipProtocolFactory factory = new SetMembershipProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(subPolWitness.getCommitmentsOnAttributes()
                            .get(pp.getPositionOfCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }


    private static SigmaProtocol retRange(PublicParameters predicatePP, Witness witness,
                                          SubPolicyProvingProtocolPublicParameters subPolPP, int position) {
        if (!(predicatePP instanceof ArbitraryRangeProofPublicParameters)) {
            throw new IllegalArgumentException("The given public parameters for the protocol does not match");
        }
        ArbitraryRangeProofPublicParameters pp = (ArbitraryRangeProofPublicParameters) predicatePP;
        pp.setCommitment(subPolPP.getCommitmentsOnAttributes().get(pp.getPositionOfCommitment())
                .getCommitmentElement());
        ArbitraryRangeProofProtocolFactory factory =
                new ArbitraryRangeProofProtocolFactory(pp, Integer.toString(position));
        if (witness instanceof EmptyWitness) {
            return factory.getVerifierProtocol();
        } else if (witness instanceof SubPolicyProvingProtocolWitness) {
            SubPolicyProvingProtocolWitness subPolWitness = ((SubPolicyProvingProtocolWitness) witness);
            return factory.getProverProtocol(subPolWitness.getCommitmentsOnAttributes()
                            .get(pp.getPositionOfCommitment()),
                    subPolWitness.getCredential().getAttributes()[pp.getPositionOfCommitment()]
                            .getZpRepresentation(subPolPP.getHashIntoZp()));
        } else {
            throw new IllegalArgumentException("The given witness is not compatible");
        }
    }

}
