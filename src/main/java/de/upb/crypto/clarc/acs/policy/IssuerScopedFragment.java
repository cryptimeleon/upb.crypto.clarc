package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.attributes.AttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.attributes.BigIntegerAttributeDefinition;
import de.upb.crypto.clarc.acs.attributes.StringAttributeDefinition;
import de.upb.crypto.clarc.acs.issuer.credentials.CredentialIssuerPublicIdentity;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.predicategeneration.equalityproofs.EqualityPublicParameterAdvancedProof;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.PredicateTypePrimitive;
import de.upb.crypto.clarc.predicategeneration.inequalityproofs.InequalityPublicParameters;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.EqualityParameterGen;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.InequalityParameterGen;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.RangeProofParameterGen;
import de.upb.crypto.clarc.predicategeneration.parametergeneration.SetMembershipParameterGen;
import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.predicategeneration.setmembershipproofs.SetMembershipPublicParameters;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import org.apache.commons.lang3.Validate;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;


public class IssuerScopedFragment implements PotentialFragmentEndPart {

    private final PolicyBuildingContext context;
    final CredentialIssuerPublicIdentity issuer;

    List<PredicatePolicyFact> facts = new ArrayList<>();
    List<Integer> attributeIndicesToDisclose = new ArrayList<>();

    private AggregationMethod aggregationMethod = null;
    // when setting an aggregation method it is not known whether they apply for the local issuer scope or should
    // aggregate multiple issuer scopes. Thus it first has to be tracked as *tentative* aggregation method and the
    // actual application has to happen delayed.
    private AggregationMethod tentativeAggregationMethod = null;

    public IssuerScopedFragment(PolicyBuildingContext context, CredentialIssuerPublicIdentity issuer) {
        this.context = context;
        this.issuer = issuer;
        context.registerAttributeSpace(issuer.getAttributeSpace());
    }

    private void applyAggregationTypeIfRequired() {
        if (tentativeAggregationMethod == null) {
            return;
        }

        if (aggregationMethod != null && tentativeAggregationMethod != aggregationMethod) {
            throw new IllegalStateException(String.format(
                    "unable to mix %s with %s aggregation method", aggregationMethod, tentativeAggregationMethod
            ));
        }
        aggregationMethod = tentativeAggregationMethod;
        tentativeAggregationMethod = null;
    }

    private void checkForExistingTentativeAggregationType() {
        if (tentativeAggregationMethod != null) {
            throw new IllegalStateException("aggregation method is already specific");
        }
    }

    public IssuerScopedFragment and() {
        checkForExistingTentativeAggregationType();
        tentativeAggregationMethod = AggregationMethod.AND;
        return this;
    }

    public IssuerScopedFragment or() {
        checkForExistingTentativeAggregationType();
        tentativeAggregationMethod = AggregationMethod.OR;
        return this;
    }

    /**
     * Starts a statement about the value of an attribute of which the actual value must be disclosed
     *
     * @param attributeName the name of the attribute
     * @return -
     */
    public AttributeFragment disclosedAttribute(String attributeName) {
        applyAggregationTypeIfRequired();
        final AttributeDefinition attributeDefinition = issuer.getAttributeSpace().get(attributeName);
        if (attributeDefinition == null) {
            throw new IllegalStateException(String.format("Unknown disclosedAttribute '%s'", attributeName));
        }
        return new AttributeFragment(this, attributeName, true);
    }

    /**
     * Starts a statement about the value of an attribute
     *
     * @param attributeName the name of the attribute
     * @return -
     */
    public AttributeFragment attribute(String attributeName) {
        applyAggregationTypeIfRequired();
        final AttributeDefinition attributeDefinition = issuer.getAttributeSpace().get(attributeName);
        if (attributeDefinition == null) {
            throw new IllegalStateException(String.format("Unknown attribute '%s'", attributeName));
        }
        return new AttributeFragment(this, attributeName, false);
    }

    /**
     * Sets the scope of the following attributes to an issuer
     *
     * @param identity The {@link CredentialIssuerPublicIdentity} of an issuer
     * @return -
     */
    public IssuerScopedFragment forIssuer(CredentialIssuerPublicIdentity identity) {
        Validate.notNull(identity, "identity must not be null");
        context.setAggregationMethod(tentativeAggregationMethod);
        tentativeAggregationMethod = null;
        finish();
        return new IssuerScopedFragment(context, identity);
    }

    private void finish() {
        if (tentativeAggregationMethod != null) {
            throw new IllegalStateException(
                    "unable to build policy: unconsumed aggegation type: " + tentativeAggregationMethod
            );
        }

        int threshold = AggregationMethod.getThreshold(aggregationMethod, facts.size());
        ThresholdPolicy thresholdPolicy = new ThresholdPolicy(threshold, facts);
        final SubPolicyPolicyFact subPolicy =
                new SubPolicyPolicyFact(issuer.getIssuerPublicKey(), thresholdPolicy);

        final SelectiveDisclosure disclosure =
                new SelectiveDisclosure(issuer.getIssuerPublicKey(), attributeIndicesToDisclose);

        context.addIssuerPolicy(subPolicy);
        context.addDisclosedAttributes(disclosure);
    }

    @Override
    public PolicyInformation build() {
        finish();
        return context.build();
    }

    private StringAttributeDefinition getStringAttributeDefinition(String attributeName) {
        final AttributeDefinition attributeDefinition = issuer.getAttributeSpace().get(attributeName);
        if (!(attributeDefinition instanceof StringAttributeDefinition)) {
            throw new IllegalArgumentException(String.format("attribute '%s' does not accept a string", attributeName));
        }
        return (StringAttributeDefinition) attributeDefinition;
    }

    private BigIntegerAttributeDefinition getBigIntegerAttributeDefinition(String attributeName) {
        final AttributeDefinition attributeDefinition = issuer.getAttributeSpace().get(attributeName);
        if (!(attributeDefinition instanceof BigIntegerAttributeDefinition)) {
            throw new IllegalArgumentException(
                    String.format("attribute '%s' does not accept an integer", attributeName)
            );
        }
        return (BigIntegerAttributeDefinition) attributeDefinition;
    }

    void addEqualityCheck(String attributeName, String value) {
        final StringAttributeDefinition attributeDefinition = getStringAttributeDefinition(attributeName);
        final int attributeIndex = issuer.getAttributeSpace().getAttributeIndex(attributeDefinition);
        final AttributeNameValuePair equalityValue = attributeDefinition.createAttribute(value);
        final EqualityPublicParameterAdvancedProof parameters = EqualityParameterGen.getEqualityPP(
                context.pp.getSingleMessageCommitmentPublicParameters(),
                equalityValue.getZpRepresentation(context.pp.getHashIntoZp()),
                attributeIndex
        );
        PredicatePolicyFact fact = new PredicatePolicyFact(parameters, PredicateTypePrimitive.EQUALITY_PUBLIC_VALUE);
        facts.add(fact);
    }

    void addInequalityCheck(String attributeName, String value) {
        final StringAttributeDefinition attributeDefinition = getStringAttributeDefinition(attributeName);
        final int attributeIndex = issuer.getAttributeSpace().getAttributeIndex(attributeDefinition);
        final AttributeNameValuePair inequalityValue = attributeDefinition.createAttribute(value);

        final PublicParameters pp = context.pp;
        final InequalityPublicParameters parameters =
                InequalityParameterGen.createInequalityPP(
                        pp.getSingleMessageCommitmentPublicParameters(),
                        pp.getBilinearMap(), attributeIndex, inequalityValue.getZpRepresentation(pp.getHashIntoZp()),
                        pp.getHashIntoZp().getTargetStructure()
                );
        PredicatePolicyFact fact = new PredicatePolicyFact(parameters, PredicateTypePrimitive.INEQUALITY_PUBLIC_VALUE);
        facts.add(fact);
    }

    void addSetCheck(String attributeName, String[] set) {
        final StringAttributeDefinition attributeDefinition = getStringAttributeDefinition(attributeName);
        if (set == null) {
            throw new IllegalArgumentException("the set must not be null");
        }
        final int attributeIndex = issuer.getAttributeSpace().getAttributeIndex(attributeDefinition);
        final Set<AttributeNameValuePair> attributeSet = Arrays.stream(set).map(attributeDefinition::createAttribute)
                .collect(Collectors.toSet());

        final PublicParameters pp = context.pp;
        final SetMembershipPublicParameters setMembershipPP = SetMembershipParameterGen.createSetMembershipPP(
                pp.getSingleMessageCommitmentPublicParameters(),
                attributeIndex, attributeSet.stream().map(
                        attr -> attr.getZpRepresentation(pp.getHashIntoZp())).collect(Collectors.toSet()
                ),
                pp.getNguyenAccumulatorPP(), pp.getHashIntoZp().getTargetStructure()
        );
        PredicatePolicyFact fact = new PredicatePolicyFact(
                setMembershipPP,
                PredicateTypePrimitive.SET_MEMBERSHIP_ATTRIBUTE
        );
        facts.add(fact);
    }

    void addRangeCheck(String attributeName, long lowerBound, long upperBound) {
        final BigIntegerAttributeDefinition attributeDefinition = getBigIntegerAttributeDefinition(attributeName);
        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("lowerBound is larger than upperBound");
        }
        final int attributeIndex = issuer.getAttributeSpace().getAttributeIndex(attributeDefinition);

        final PublicParameters pp = context.pp;
        final ArbitraryRangeProofPublicParameters rangePP = RangeProofParameterGen.getRangePP(
                pp.getSingleMessageCommitmentPublicParameters(),
                BigInteger.valueOf(lowerBound), BigInteger.valueOf(upperBound),
                attributeIndex, pp.getZp(), pp.getNguyenAccumulatorPP()
        );
        PredicatePolicyFact fact = new PredicatePolicyFact(
                rangePP,
                PredicateTypePrimitive.ATTRIBUTE_IN_RANGE
        );
        facts.add(fact);
    }

    void addDisclosedAttribute(String attributeName) {
        final int attributeIndex = issuer.getAttributeSpace().getAttributeIndex(attributeName);
        this.attributeIndicesToDisclose.add(attributeIndex);
    }
}
