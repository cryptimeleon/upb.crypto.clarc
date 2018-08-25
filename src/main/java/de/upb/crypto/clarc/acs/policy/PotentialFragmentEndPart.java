package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.craco.interfaces.policy.Policy;

interface PotentialFragmentEndPart {
    /**
     * Triggers the build of the policy
     *
     * @return The {@link Policy} which was described using the fluent api
     */
    PolicyInformation build();
}
