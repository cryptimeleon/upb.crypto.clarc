package de.upb.crypto.clarc.acs.serialization.classes;

import de.upb.crypto.clarc.acs.policy.PolicyInformation;
import de.upb.crypto.clarc.acs.testdataprovider.IssuerTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.ParameterTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.PredicatePrimitiveTestdataProvider;
import de.upb.crypto.clarc.acs.testdataprovider.UserAndSystemManagerTestdataProvider;
import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.acs.verifier.credentials.VerificationResult;
import de.upb.crypto.clarc.predicategeneration.PredicatePublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityProofProtocol;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SigmaProtocolPolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.FiatShamirHeuristic;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirProof;
import de.upb.crypto.clarc.utils.StandaloneTestParams;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.hash.impl.SHA256HashFunction;
import de.upb.crypto.math.interfaces.structures.GroupElement;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

public class PolicyParams {

    public static Collection<StandaloneTestParams> get() {

        ArrayList<StandaloneTestParams> toReturn = new ArrayList<>();

        ParameterTestdataProvider clarcProvider = new ParameterTestdataProvider();
        UserAndSystemManagerTestdataProvider userProvider =
                new UserAndSystemManagerTestdataProvider(clarcProvider.getPublicParameters());
        IssuerTestdataProvider issuerProvider = new IssuerTestdataProvider(clarcProvider.getPublicParameters(),
                clarcProvider.getSignatureScheme(), userProvider.getUserSecret());
        PredicatePrimitiveTestdataProvider predicateProvider =
                new PredicatePrimitiveTestdataProvider(clarcProvider.getPublicParameters(),
                        issuerProvider.getCredentialWitfDefaultAttributeSpace());

        InequalityProofProtocol inequalityProofProtocol = predicateProvider.getInequalityProtocol(0, "",
                predicateProvider.getZPRepresentationForAttrAtPos(0).getInteger().add(BigInteger.ONE));
        PredicatePolicyFact predicatePolicyFact = new PredicatePolicyFact((PredicatePublicParameters)
                inequalityProofProtocol.getPublicParameters(),
                PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE);

        SubPolicyPolicyFact subPolicyPolicyFact = new SubPolicyPolicyFact(
                issuerProvider.getIssuerPublicKey().getRepresentation(), new ThresholdPolicy(1, predicatePolicyFact));

        GroupElement testElement = clarcProvider.getPublicParameters().getBilinearMap().getG1().getNeutralElement();
        RepresentableSignature signature = new RepresentableSignature(new PSSignature(testElement, testElement));

        FiatShamirHeuristic fiatShamirHeuristic =
                new FiatShamirHeuristic(inequalityProofProtocol, new SHA256HashFunction());
        FiatShamirProof proof = fiatShamirHeuristic.prove();
        VerificationResult verificationResult = new VerificationResult(true, proof, new PolicyInformation(
                clarcProvider.getPP(), new ThresholdPolicy(1, predicatePolicyFact),
                issuerProvider.currentAttributeSpaces(), null, true),
                userProvider.getIdentity().getPseudonym(), signature);

        toReturn.add(new StandaloneTestParams(PredicatePolicyFact.class, predicatePolicyFact));
        toReturn.add(new StandaloneTestParams(SubPolicyPolicyFact.class, subPolicyPolicyFact));
        toReturn.add(new StandaloneTestParams(SigmaProtocolPolicyFact.class, new SigmaProtocolPolicyFact
                (inequalityProofProtocol, 0)));

        toReturn.add(new StandaloneTestParams(PolicyInformation.class, new PolicyInformation(
                clarcProvider.getPP(), new ThresholdPolicy(1, predicatePolicyFact),
                issuerProvider.currentAttributeSpaces(), null, true)));
        toReturn.add(new StandaloneTestParams(VerificationResult.class, verificationResult));

        return toReturn;
    }
}