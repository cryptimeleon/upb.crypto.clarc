package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuer;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.InequalityParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.serialization.converter.JSONConverter;

import java.math.BigInteger;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Provide {@link ProtocolFactoryExecutionParams} for {@link Policy}s using the predicate type
 * {@link PredicateTypePrimitive#INEQUALITY_PUBLIC_VALUE}
 */
public class InequalityPolicies {

    private static final String serializedAgeAttributeDef =
            "{\"attributeName\":\"age\",\"maxValue\":\"<BigInteger>c8\"," +
                    "\"minValue\":\"<BigInteger>1\"}";

    private static final String serializedGenderAttributeDef = "{\"attributeName\":\"gender\"," +
            "\"verificationRegex\":\"[mM]|[fF]\"}";

    /**
     * Creates {@link ProtocolFactoryExecutionParams} for a multiple {@link Policy} containing sub policies of
     * {@link de.upb.crypto.clarc.acs.issuer.Issuer}s which utilize inequality proofs
     *
     * @param clarcPP public parameters of the system
     * @param usk     secret of the user which wants to fulfill the policy
     * @return {@link ProtocolFactoryExecutionParams} for {@link SubPolicyPolicyFact}s using inequality proofs
     */
    public static Collection<? extends ProtocolFactoryExecutionParams> get(PublicParameters clarcPP,
                                                                           UserSecret usk) {
        ProtocolFactoryExecutionParams simpleInequalityParam = getSimpleInequalityParams(clarcPP, usk);

        SelectiveDisclosure disclosure = new SelectiveDisclosure(
                simpleInequalityParam.fulfillingCredentials[0].getIssuerPublicKeyRepresentation(),
                Collections.singletonList(0));
        ProtocolFactoryExecutionParams simpleInequalityParamWithDisclosure =
                new ProtocolFactoryExecutionParams(simpleInequalityParam.issuers,
                        simpleInequalityParam.fulfillingCredentials, new SelectiveDisclosure[]{disclosure},
                        simpleInequalityParam.policy);

        CredentialIssuer issuer = simpleInequalityParam.issuers[0];
        PSCredential credential = simpleInequalityParam.fulfillingCredentials[0];
        SubPolicyPolicyFact subPolicy = (SubPolicyPolicyFact) simpleInequalityParam.policy;

        List<AttributeDefinition> attributeDefinitions =
                issuer.getPublicIdentity().getAttributeSpace().getDefinitions();

        IssuerKeyPairFactory issuerKeyPairFactory = new IssuerKeyPairFactory();

        CredentialIssuer issuer2 = new CredentialIssuer(
                clarcPP,
                issuerKeyPairFactory.create(clarcPP, attributeDefinitions.size()),
                attributeDefinitions);

        CredentialIssuer issuer3 = new CredentialIssuer(
                clarcPP,
                issuerKeyPairFactory.create(clarcPP, attributeDefinitions.size()),
                attributeDefinitions);

        Policy policyFromFixedIssuer = new SubPolicyPolicyFact(issuer.getPublicIdentity().getIssuerPublicKey(),
                subPolicy.getSubPolicy());

        Policy policyFromIssuer2 = new SubPolicyPolicyFact(issuer2.getPublicIdentity().getIssuerPublicKey(),
                subPolicy.getSubPolicy());
        Policy policyFromIssuer3 = new SubPolicyPolicyFact(issuer3.getPublicIdentity().getIssuerPublicKey(),
                subPolicy.getSubPolicy());

        Policy intermediatePolicy = new ThresholdPolicy(2, policyFromIssuer2, policyFromIssuer3);

        Policy policy = new ThresholdPolicy(1, policyFromFixedIssuer, intermediatePolicy);

        ProtocolFactoryExecutionParams complexInequalityParams =
                new ProtocolFactoryExecutionParams(new CredentialIssuer[]{issuer, issuer2, issuer3},
                        new PSCredential[]{credential, null, null}, null, policy);


        SelectiveDisclosure[] disclosures = new SelectiveDisclosure[]{
                new SelectiveDisclosure(credential.getIssuerPublicKeyRepresentation(), Collections.singletonList(0)),
                null,
                null};
        ProtocolFactoryExecutionParams complexInequalityWithDisclosureParams =
                new ProtocolFactoryExecutionParams(new CredentialIssuer[]{issuer, issuer2, issuer3},
                        new PSCredential[]{credential, null, null}, disclosures, policy);

        return Arrays.asList(
                simpleInequalityParam,
                simpleInequalityParamWithDisclosure,
                complexInequalityParams,
                complexInequalityWithDisclosureParams
        );
    }

    /**
     * Creates {@link ProtocolFactoryExecutionParams} for a simple {@link Policy} containing only the sub policy of
     * a single {@link de.upb.crypto.clarc.acs.issuer.Issuer} which demands two fulfilled inequality proofs
     *
     * @param clarcPP public parameters of the system
     * @param usk     secret of the user which wants to fulfill the policy
     * @return {@link ProtocolFactoryExecutionParams} for a simple {@link SubPolicyPolicyFact} proof using inequality
     */
    private static ProtocolFactoryExecutionParams getSimpleInequalityParams(PublicParameters clarcPP,
                                                                            UserSecret usk) {
        JSONConverter converter = new JSONConverter();

        BigIntegerAttributeDefinition age =
                new BigIntegerAttributeDefinition(converter.deserialize(serializedAgeAttributeDef));
        StringAttributeDefinition gender =
                new StringAttributeDefinition(converter.deserialize(serializedGenderAttributeDef));

        List<AttributeDefinition> attributeDefinitions = Arrays.asList(age, gender);
        IssuerKeyPairFactory keyPairFactory = new IssuerKeyPairFactory();
        IssuerKeyPair issuerKeyPair = keyPairFactory.create(clarcPP, attributeDefinitions.size());

        CredentialIssuer issuer = new CredentialIssuer(clarcPP, issuerKeyPair, attributeDefinitions);

        List<AttributeNameValuePair> attributesForCredential = new ArrayList<>();
        attributesForCredential.add(age.createAttribute(BigInteger.valueOf(18)));
        attributesForCredential.add(gender.createAttribute("f"));

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

        AttributeNameValuePair inequalAttributeAge = age.createAttribute(BigInteger.valueOf(20));
        AttributeNameValuePair inequalAttributeGender = gender.createAttribute("m");

        InequalityPublicParameters ageInequalityPP =
                InequalityParameterGen.createInequalityPP(clarcPP.getSingleMessageCommitmentPublicParameters(),
                        clarcPP.getBilinearMap(), 0, inequalAttributeAge.getZpRepresentation(clarcPP.getHashIntoZp()),
                        clarcPP.getHashIntoZp().getTargetStructure());

        InequalityPublicParameters genderInequalityPP =
                InequalityParameterGen.createInequalityPP(clarcPP.getSingleMessageCommitmentPublicParameters(),
                        clarcPP.getBilinearMap(), 1,
                        inequalAttributeGender.getZpRepresentation(clarcPP.getHashIntoZp()),
                        clarcPP.getHashIntoZp().getTargetStructure());
        PredicatePolicyFact inequalAge = new PredicatePolicyFact(
                ageInequalityPP, PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE
        );
        PredicatePolicyFact inequalGender = new PredicatePolicyFact(
                genderInequalityPP, PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE
        );

        ThresholdPolicy policyWithProtocolLeaves = new ThresholdPolicy(2, inequalAge, inequalGender);
        Policy policy = new SubPolicyPolicyFact(issuerKeyPair.getVerificationKey().getRepresentation(),
                policyWithProtocolLeaves);

        return new ProtocolFactoryExecutionParams(new CredentialIssuer[]{issuer}, new
                PSCredential[]{credential}, null,
                policy);
    }
}
