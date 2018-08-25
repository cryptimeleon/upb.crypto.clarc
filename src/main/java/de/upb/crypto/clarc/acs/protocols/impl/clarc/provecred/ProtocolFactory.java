package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.subpolicyproving.SubPolicyProvingProtocolFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.credentials.SignatureCredential;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.damgardtechnique.DamgardTechnique;
import de.upb.crypto.clarc.protocols.parameters.EmptyWitness;
import de.upb.crypto.craco.commitment.interfaces.CommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.math.serialization.Representation;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

/**
 * A {@link de.upb.crypto.clarc.acs.protocols.ProtocolFactory} which generates protocols to prove/verify the fulfillment of a {@link Policy} using
 * {@link PSCredential}
 */
public abstract class ProtocolFactory implements de.upb.crypto.clarc.acs.protocols.ProtocolFactory {

    protected final PSExtendedSignatureScheme signatureScheme;
    protected final ProtocolParameters protocolParameters;
    protected final PublicParameters publicParameters;


    protected final Map<Representation, AttributeSpace> attributespaceMapping;
    protected final SelectiveDisclosure[] disclosures;

    protected final ThresholdPolicy policy;

    /**
     * Instantiates a ProtocolFactory with given public and protocol parameters.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     *
     * @param protocolParameters shared input for all protocol instances (prover and verifier)
     * @param publicParameters   the system's public parameters
     * @param attributeSpaces    currently available attribute spaces
     * @param policy             the policy of which the fulfillment is to be proven
     */
    public ProtocolFactory(ProtocolParameters protocolParameters, PublicParameters publicParameters,
                           List<AttributeSpace> attributeSpaces, Policy policy) {
        this(protocolParameters, publicParameters, attributeSpaces, policy, null);
    }

    /**
     * Instantiates a ProtocolFactory with given public and protocol parameters.
     * The currently available attribute spaces are needed to correctly parse the policy to be fulfilled.
     *
     * @param protocolParameters shared input for all protocol instances (prover and verifier)
     * @param publicParameters   the system's public parameters
     * @param attributeSpaces    currently available attribute spaces
     * @param policy             the policy of which the fulfillment is to be proven
     * @param disclosures        attributes to be disclosed
     */
    public ProtocolFactory(ProtocolParameters protocolParameters, PublicParameters publicParameters,
                           List<AttributeSpace> attributeSpaces, Policy policy,
                           SelectiveDisclosure[] disclosures) {
        this.protocolParameters = protocolParameters;
        this.publicParameters = publicParameters;
        this.signatureScheme = PublicParametersFactory.getSignatureScheme(publicParameters);

        this.attributespaceMapping =
                attributeSpaces.stream()
                        .collect(Collectors.toMap(
                                AttributeSpace::getIssuerPublicKey,
                                Function.identity(),
                                (a1, a2) -> a1));

        if (policy instanceof ThresholdPolicy) {
            this.policy = (ThresholdPolicy) policy;
        } else if (policy instanceof SubPolicyPolicyFact) {
            this.policy = new ThresholdPolicy(1, policy);
        } else {
            throw new IllegalArgumentException("Unsupported policy: " + policy.getClass().getName());
        }

        int numberOfSubPolicies = collectSubPolicis(this.policy).size();

        if (disclosures != null) {
            if (disclosures.length != numberOfSubPolicies) {
                throw new IllegalArgumentException("The number of provided disclosures does not match the number of" +
                        " sub policies");
            }
            this.disclosures = disclosures;
        } else {
            this.disclosures = new SelectiveDisclosure[numberOfSubPolicies];
        }

    }

    /**
     * Convenience method to determine the order of {@link SignatureCredential} to be used for proving fulfillment of
     * the given {@link ThresholdPolicy}.
     *
     * @param policy {@link ThresholdPolicy} to collect {@link SubPolicyPolicyFact} leaves from
     * @return the {@link SubPolicyPolicyFact} contained in the given {@link ThresholdPolicy} in the order their
     * corresponding {@link SigmaProtocol} will be executed.
     */
    public static SubPolicyPolicyFact[] getSubPolicies(ThresholdPolicy policy) {
        return collectSubPolicis(policy).toArray(new SubPolicyPolicyFact[0]);
    }

    /**
     * Collects all sub policies found as leaves of the given {@link ThresholdPolicy}
     *
     * @param policy {@link ThresholdPolicy} to collect {@link SubPolicyPolicyFact} leaves from
     * @return the {@link SubPolicyPolicyFact} contained in the given {@link ThresholdPolicy} in the order their
     * corresponding {@link SigmaProtocol} will be executed.
     */
    private static List<SubPolicyPolicyFact> collectSubPolicis(ThresholdPolicy policy) {
        List<SubPolicyPolicyFact> subPolicies = new ArrayList<>();
        for (Policy child : policy.getChildren()) {
            if (child instanceof ThresholdPolicy) {
                subPolicies.addAll(collectSubPolicis((ThresholdPolicy) child));
            } else if (child instanceof SubPolicyPolicyFact) {
                subPolicies.add((SubPolicyPolicyFact) child);
            } else {
                throw new IllegalArgumentException("The given policy is malformed. It must only contain " +
                        ThresholdPolicy.class.getName() + " and " +
                        SubPolicyPolicyFact.class.getName() + ". Found " + child.getClass().getName());

            }
        }
        return subPolicies;
    }

    /**
     * Apply {@link DamgardTechnique} on the given protocol. This method can be executed on the "highest" level of the
     * protocols to ensure concurrent zero-knowledgeness during the protocol execution.
     *
     * <p>
     * If this method is invoked on an intermediate {@link SigmaProtocol} an underlying
     * {@link ProofOfPartialKnowledgeProtocol} will fail as it depends on the {@link SigmaProtocol}
     * </p>
     *
     * @param publicParameters the system's public parameters
     * @param protocol         the protocol to apply damgard's technique on
     * @return An executable version of the given protocol which ensures concurrent zero-knowledgeness
     */
    public static InteractiveThreeWayAoK applyDamgardsTechnique(PublicParameters publicParameters,
                                                                SigmaProtocol protocol) {
        CommitmentScheme commitmentScheme =
                PublicParametersFactory.getMultiMessageCommitmentScheme(publicParameters);

        return new DamgardTechnique(protocol, commitmentScheme);
    }

    protected SigmaProtocol createProtocolForSubpolicy(SubPolicyPolicyFact subPolicy, de.upb.crypto.clarc.protocols.parameters.Witness witness) {
        PedersenCommitmentScheme commitmentScheme =
                PublicParametersFactory.getSingleMessageCommitmentScheme(publicParameters);
        SubPolicyProvingProtocolFactory factory =
                new SubPolicyProvingProtocolFactory(commitmentScheme, signatureScheme,
                        protocolParameters.getPseudonym().getCommitmentValue(),
                        attributespaceMapping.get(subPolicy.getIssuerPublicKeyRepresentation()),
                        new HashMap<>(), subPolicy.getSubPolicy(), publicParameters.getHashIntoZp(),
                        publicParameters.getBilinearMap());

        if (witness instanceof Witness) {
            Witness clarcWitness = (Witness) witness;
            PSCredential credential = clarcWitness.getCredential();

            factory =
                    new SubPolicyProvingProtocolFactory(commitmentScheme, signatureScheme,
                            protocolParameters.getPseudonym().getCommitmentValue(),
                            attributespaceMapping.get(subPolicy.getIssuerPublicKeyRepresentation()),
                            clarcWitness.getDisclosedElements(), subPolicy.getSubPolicy(),
                            publicParameters.getHashIntoZp(),
                            publicParameters.getBilinearMap());

            if (credential != null && !credential.getIssuerPublicKeyRepresentation()
                    .equals(subPolicy.getIssuerPublicKeyRepresentation())) {
                throw new IllegalArgumentException("The given credential's ipk does not match the one required by" +
                        " the policy.");
            }
            if (credential != null) {
                return factory
                        .getProverProtocol(credential, clarcWitness.getUsk().getUsk(), clarcWitness.getNymRandom());
            }
            return factory.getVerifieryProtocol();
        } else {
            return factory.getVerifieryProtocol();
        }
    }

    protected SigmaProtocol createProtocolForSubpolicy(SubPolicyPolicyFact subPolicy) {
        return createProtocolForSubpolicy(subPolicy, new EmptyWitness());
    }

}
