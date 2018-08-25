package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.RangeProofParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Provide {@link ProtocolFactoryExecutionParams} for {@link Policy}s using the predicate type
 * {@link PredicateTypePrimitive#INEQUALITY_PUBLIC_VALUE}
 */
public class RangeProofPolicies {

    private static final String serializedAgeAttributeDef =
            "{\"attributeName\":\"age\",\"maxValue\":\"<BigInteger>c8\",\"minValue\":\"<BigInteger>1\"}";

    /**
     * Creates {@link ProtocolFactoryExecutionParams} for a simple {@link Policy} containing only the sub policy of
     * a single {@link de.upb.crypto.clarc.acs.issuer.Issuer} which demands a fulfilled set membership proof
     *
     * @param clarcPP public parameters of the system
     * @param usk     secret of the user which wants to fulfill the policy
     * @return {@link ProtocolFactoryExecutionParams} for a simple {@link SubPolicyPolicyFact} proof using set
     * membership
     */
    public static ProtocolFactoryExecutionParams getSimpleRangeProofParams(PublicParameters clarcPP,
                                                                           UserSecret usk) {
        JSONConverter converter = new JSONConverter();

        BigIntegerAttributeDefinition age =
                new BigIntegerAttributeDefinition(converter.deserialize(serializedAgeAttributeDef));

        List<AttributeDefinition> attributeDefinitions = Collections.singletonList(age);
        IssuerKeyPairFactory keyPairFactory = new IssuerKeyPairFactory();
        IssuerKeyPair issuerKeyPair = keyPairFactory.create(clarcPP, attributeDefinitions.size());

        CredentialIssuer issuer = new CredentialIssuer(clarcPP, issuerKeyPair, attributeDefinitions);

        List<AttributeNameValuePair> attributesForCredential = new ArrayList<>();
        attributesForCredential.add(age.createAttribute(BigInteger.valueOf(21)));


        attributesForCredential =
                attributesForCredential.stream()
                        .map(attr -> AttributeNameValuePair
                                .getAttributeForIssuer(issuerKeyPair.getVerificationKey(), attr))
                        .collect(Collectors.toList());

        List<RingElementPlainText> messages = new ArrayList<>(attributeDefinitions.size() + 1);
        messages.add(new RingElementPlainText(usk.getUsk()));
        attributesForCredential.stream()
                .map(attr -> new RingElementPlainText(attr.getZpRepresentation(clarcPP.getHashIntoZp())))
                .forEachOrdered(messages::add);
        MessageBlock messageBlock = new MessageBlock(messages);

        PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(clarcPP);

        PSSignature signature = (PSSignature) signatureScheme.sign(messageBlock, issuerKeyPair.getSigningKey());
        PSCredential credential = new PSCredential(
                signature.getRepresentation(),
                attributesForCredential.toArray(new AttributeNameValuePair[attributeDefinitions.size()]),
                issuerKeyPair.getVerificationKey().getRepresentation());


        ArbitraryRangeProofPublicParameters rangePP =
                RangeProofParameterGen.getRangePP(clarcPP.getSingleMessageCommitmentPublicParameters(),
                        BigInteger.valueOf(18), BigInteger.valueOf(200), 0,
                        clarcPP.getZp(), clarcPP.getNguyenAccumulatorPP());

        PredicatePolicyFact rangeProof = new PredicatePolicyFact(
                rangePP, PredicateTypePrimitive.ATTRIBUTE_IN_RANGE
        );

        ThresholdPolicy policyWithProtocolLeaves = new ThresholdPolicy(1, rangeProof);
        Policy policy = new SubPolicyPolicyFact(issuerKeyPair.getVerificationKey().getRepresentation(),
                policyWithProtocolLeaves);

        return new ProtocolFactoryExecutionParams(new CredentialIssuer[]{issuer}, new
                PSCredential[]{credential}, null,
                policy);
    }
}
