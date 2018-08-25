package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgePublicParameters;
import de.upb.crypto.clarc.predicategeneration.policies.SigmaProtocolPolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Factory for generating a verifier protocol to verify fulfillment of a {@link Policy}
 */
public class VerifierProtocolFactory extends ProtocolFactory {

    /**
     * Instantiates a {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} with given public and protocol parameters.
     * It is able to generate a protocol to verify the fulfillment of a {@link Policy}.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     *
     * @param protocolParameters shared input for all protocol instances (prover and verifier)
     * @param publicParameters   the system's public parameters
     * @param attributeSpaces    currently available attribute spaces
     * @param policy             the policy which fulfillment is to be proven
     */
    public VerifierProtocolFactory(ProtocolParameters protocolParameters,
                                   PublicParameters publicParameters,
                                   List<AttributeSpace> attributeSpaces, Policy policy) {
        this(protocolParameters, publicParameters, attributeSpaces, policy, null);
    }

    /**
     * Instantiates a {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} with given public and protocol parameters.
     * It is able to generate a protocol to verify the fulfillment of a {@link Policy}.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     * <p>
     * The order of the given {@link SelectiveDisclosure} must match the order of
     * {@link ProtocolFactory#getSubPolicies} associated with the same issuer. If there is no
     * {@link SelectiveDisclosure} available for a certain sub policy, null is expected at the corresponding position
     * in the array.
     * </p>
     *
     * @param protocolParameters shared input for all protocol instances (prover and verifier)
     * @param publicParameters   the system's public parameters
     * @param attributeSpaces    currently available attribute spaces
     * @param policy             the policy which fulfillment is to be proven
     * @param disclosures        attributes to be disclosed
     */
    public VerifierProtocolFactory(ProtocolParameters protocolParameters,
                                   PublicParameters publicParameters,
                                   List<AttributeSpace> attributeSpaces, Policy policy,
                                   SelectiveDisclosure[] disclosures) {
        super(protocolParameters, publicParameters, attributeSpaces, policy, disclosures);
    }

    @Override
    public PolicyProvingProtocol getProtocol() {
        ThresholdPolicy transformedPolicy = transformPolicy(policy, new AtomicInteger(0));

        ProofOfPartialKnowledgePublicParameters popkPublicParameters =
                new ProofOfPartialKnowledgePublicParameters(protocolParameters.getLsssProvider(),
                        publicParameters.getZp());
        ProofOfPartialKnowledgeProtocol innerProtocol =
                new ProofOfPartialKnowledgeProtocol(popkPublicParameters, transformedPolicy);
        return new PolicyProvingProtocol(innerProtocol);
    }

    /**
     * Transforms the given {@link ThresholdPolicy} with contains {@link SubPolicyPolicyFact} as leaves into a
     * {@link ThresholdPolicy} which contains {@link SigmaProtocolPolicyFact} as leaves as required by the
     * {@link ProofOfPartialKnowledgeProtocol}.
     * <br>
     * For this transformation {@link ProtocolFactory#createProtocolForSubpolicy} is called for every contained
     * sub policy.
     *
     * @param policy      the policy to transform
     * @param leafCounter stateful counter to ensure unique ids provided to every created
     *                    {@link SigmaProtocolPolicyFact}
     * @return {@link ThresholdPolicy} which contains {@link SigmaProtocolPolicyFact} as leaves
     */
    private ThresholdPolicy transformPolicy(ThresholdPolicy policy, AtomicInteger leafCounter) {
        List<Policy> children = policy.getChildren();
        List<Policy> transformedChildren = new ArrayList<>(children.size());
        for (Policy childPolicy : children) {
            if (childPolicy instanceof SubPolicyPolicyFact) {
                SubPolicyPolicyFact subPolicy = (SubPolicyPolicyFact) childPolicy;
                int leafId = leafCounter.getAndIncrement();

                SigmaProtocol protocol = createProtocolForSubpolicy(subPolicy);

                transformedChildren.add(new SigmaProtocolPolicyFact(protocol, leafId));
            } else if (childPolicy instanceof ThresholdPolicy) {
                transformedChildren.add(transformPolicy((ThresholdPolicy) childPolicy, leafCounter));
            } else {
                throw new IllegalArgumentException("Malformed Policy!");
            }
        }
        return new ThresholdPolicy(policy.getThreshold(), transformedChildren);
    }

}
