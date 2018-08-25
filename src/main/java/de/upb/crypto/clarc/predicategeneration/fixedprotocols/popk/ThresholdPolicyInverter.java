package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.interfaces.policy.PolicyFact;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;

import java.util.ArrayList;
import java.util.List;

public class ThresholdPolicyInverter {

    /**
     * Inverts the given {@link ThresholdPolicy} such that for each contained {@link ThresholdPolicy} with threshold t
     * and n children a new {@link ThresholdPolicy} is created with threshold (1 + n - t)
     *
     * @param policy {@link ThresholdPolicy} to invert
     * @return the inverted {@link ThresholdPolicy}
     */
    public static ThresholdPolicy invertThresholdPolicy(ThresholdPolicy policy) {
        int numberOfChildren = policy.getChildren().size();
        int invertedThreshold = 1 + numberOfChildren - policy.getThreshold();

        List<Policy> children = new ArrayList<>(numberOfChildren);
        for (Policy childPolicy : policy.getChildren()) {
            if (childPolicy instanceof PolicyFact) {
                children.add(childPolicy);
            } else if (childPolicy instanceof ThresholdPolicy) {
                children.add(invertThresholdPolicy((ThresholdPolicy) childPolicy));
            } else {
                throw new IllegalArgumentException("Malformed Policy!");
            }
        }
        return new ThresholdPolicy(invertedThreshold, children);
    }
}
