package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.attributes.AttributeSpace;
import de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred.SelectiveDisclosure;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.predicategeneration.policies.SubPolicyPolicyFact;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;

import java.util.ArrayList;
import java.util.List;

class PolicyBuildingContext {
    final PublicParameters pp;
    private final boolean isMasterCredentialRequired;
    List<Policy> issuerPolicies = new ArrayList<>();
    private List<AttributeSpace> usedAttributeSpaces = new ArrayList<>();
    private List<SelectiveDisclosure> requiredDisclosures = new ArrayList<>();
    private AggregationMethod aggregationMethod;

    PolicyBuildingContext(PublicParameters pp, boolean isMasterCredentialRequired) {
        this.pp = pp;
        this.isMasterCredentialRequired = isMasterCredentialRequired;
    }

    void registerAttributeSpace(AttributeSpace space) {
        usedAttributeSpaces.add(space);
    }

    void addIssuerPolicy(SubPolicyPolicyFact subPolicy) {
        issuerPolicies.add(subPolicy);
    }

    void addDisclosedAttributes(SelectiveDisclosure selectiveDisclosure) {
        requiredDisclosures.add(selectiveDisclosure);
    }

    void setAggregationMethod(AggregationMethod aggregationMethod) {
        if (this.aggregationMethod == null) {
            this.aggregationMethod = aggregationMethod;
        }
        if (this.aggregationMethod != aggregationMethod) {
            throw new IllegalStateException(String.format(
                    "unable to change previously defined aggregation method %s to %s",
                    this.aggregationMethod,
                    aggregationMethod
            ));
        }
    }

    public PolicyInformation build() {
        final int threshold = AggregationMethod.getThreshold(aggregationMethod, issuerPolicies.size());
        final ThresholdPolicy policy = new ThresholdPolicy(threshold, issuerPolicies);
        final SelectiveDisclosure[] selectiveDisclosures =
                requiredDisclosures.toArray(new SelectiveDisclosure[requiredDisclosures.size()]);
        return new PolicyInformation(pp, policy, usedAttributeSpaces, selectiveDisclosures, isMasterCredentialRequired);
    }
}
