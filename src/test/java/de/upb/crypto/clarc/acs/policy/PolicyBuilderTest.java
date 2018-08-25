package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.InequalityParameterGen;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.RangeProofParameterGen;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.SetMembershipParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static de.upb.crypto.clarc.acs.policy.PolicyBuilder.policy;
import static org.junit.jupiter.api.Assertions.assertEquals;

public class PolicyBuilderTest {
    private AttributeNameValuePair createStringAttribute(CredentialIssuerPublicIdentity issuerPublicIdentity,
                                                         String name,
                                                         String value) {
        final StringAttributeDefinition attributeDefinition =
                (StringAttributeDefinition) issuerPublicIdentity.getAttributeSpace().get(name);
        return attributeDefinition.createAttribute(value);
    }

    @Test
    void testSingleIssuerSingleAttributeInequality() {
        CredentialIssuerPublicIdentity issuerPublicIdentity = new CredentialIssuerPublicIdentity(
                null,
                Collections.singletonList(
                        new StringAttributeDefinition("role", null)
                ));

        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        final PublicParameters pp = ppFactory.create();
        final PolicyInformation policyInformation = policy(pp)
                .forIssuer(issuerPublicIdentity)
                .attribute("role").isNot("admin")
                .build();

        final AttributeNameValuePair adminRoleAttribute = createStringAttribute(issuerPublicIdentity, "role", "admin");

        final InequalityPublicParameters inequalityPublicParameters =
                InequalityParameterGen.createInequalityPP(
                        pp.getSingleMessageCommitmentPublicParameters(), pp.getBilinearMap(),
                        0, adminRoleAttribute.getZpRepresentation(pp.getHashIntoZp()),
                        pp.getHashIntoZp().getTargetStructure()
                );
        final PredicatePolicyFact predicatePolicyFact = new PredicatePolicyFact(inequalityPublicParameters,
                PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE);

        final SubPolicyPolicyFact subPolicy =
                new SubPolicyPolicyFact(issuerPublicIdentity.getIssuerPublicKey(), predicatePolicyFact);
        final Policy manuallyCreatedPolicy = new ThresholdPolicy(1, subPolicy);
        assertEquals(manuallyCreatedPolicy, policyInformation.getPolicy());

        assertEquals(
                1,
                policyInformation.getUsedAttributeSpaces().size(),
                "expected a single attribute space"
        );
        assertEquals(
                issuerPublicIdentity.getAttributeSpace(),
                policyInformation.getUsedAttributeSpaces().get(0),
                "expected attribute the only attribute space to be the one of the issuer"
        );
    }

    @Test
    void testSingleIssuerSingleAttributeSetMembership() {
        CredentialIssuerPublicIdentity issuerPublicIdentity = new CredentialIssuerPublicIdentity(
                null,
                Collections.singletonList(
                        new StringAttributeDefinition("role", null)
                ));

        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        final PublicParameters pp = ppFactory.create();
        final PolicyInformation policyInformation = policy(pp)
                .forIssuer(issuerPublicIdentity)
                .attribute("role").isInSet("admin", "user")
                .build();

        final AttributeNameValuePair adminRoleAttribute = createStringAttribute(issuerPublicIdentity, "role", "admin");
        final AttributeNameValuePair userRoleAttribute = createStringAttribute(issuerPublicIdentity, "role", "user");

        Set<AttributeNameValuePair> set = Stream.of(adminRoleAttribute, userRoleAttribute).collect(Collectors.toSet());

        final SetMembershipPublicParameters setMembershipPublicParameters =
                SetMembershipParameterGen.createSetMembershipPP(
                        pp.getSingleMessageCommitmentPublicParameters(),
                        0, set.stream().map(
                                attr -> attr.getZpRepresentation(pp.getHashIntoZp())).collect(Collectors.toSet()
                        ),
                        pp.getNguyenAccumulatorPP(), pp.getHashIntoZp().getTargetStructure()
                );
        final PredicatePolicyFact predicatePolicyFact = new PredicatePolicyFact(
                setMembershipPublicParameters,
                PredicateTypePrimitive.SET_MEMBERSHIP_ATTRIBUTE
        );

        final SubPolicyPolicyFact subPolicy =
                new SubPolicyPolicyFact(issuerPublicIdentity.getIssuerPublicKey(), predicatePolicyFact);
        final Policy manuallyCreatedPolicy = new ThresholdPolicy(1, subPolicy);
        assertEquals(manuallyCreatedPolicy, policyInformation.getPolicy());

        assertEquals(
                1,
                policyInformation.getUsedAttributeSpaces().size(),
                "expected a single attribute space"
        );
        assertEquals(
                issuerPublicIdentity.getAttributeSpace(),
                policyInformation.getUsedAttributeSpaces().get(0),
                "expected attribute the only attribute space to be the one of the issuer"
        );
    }

    @Test
    void testSingleIssuerSingleAttributeRange() {
        CredentialIssuerPublicIdentity issuerPublicIdentity = new CredentialIssuerPublicIdentity(
                null,
                Collections.singletonList(
                        new BigIntegerAttributeDefinition("age", BigInteger.valueOf(0), BigInteger.valueOf(200))
                ));

        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        final PublicParameters pp = ppFactory.create();
        final PolicyInformation policyInformation = policy(pp)
                .forIssuer(issuerPublicIdentity)
                .attribute("age").isInRange(18, 200)
                .build();


        final ArbitraryRangeProofPublicParameters rangePP = RangeProofParameterGen.getRangePP(
                pp.getSingleMessageCommitmentPublicParameters(), BigInteger.valueOf(18), BigInteger.valueOf(200),
                0, pp.getZp(), pp.getNguyenAccumulatorPP()
        );
        final PredicatePolicyFact predicatePolicyFact = new PredicatePolicyFact(
                rangePP,
                PredicateTypePrimitive.ATTRIBUTE_IN_RANGE
        );

        final SubPolicyPolicyFact subPolicy =
                new SubPolicyPolicyFact(issuerPublicIdentity.getIssuerPublicKey(), predicatePolicyFact);
        final Policy manuallyCreatedPolicy = new ThresholdPolicy(1, subPolicy);
        assertEquals(manuallyCreatedPolicy, policyInformation.getPolicy());

        assertEquals(
                1,
                policyInformation.getUsedAttributeSpaces().size(),
                "expected a single attribute space"
        );
        assertEquals(
                issuerPublicIdentity.getAttributeSpace(),
                policyInformation.getUsedAttributeSpaces().get(0),
                "expected attribute the only attribute space to be the one of the issuer"
        );
    }
}
