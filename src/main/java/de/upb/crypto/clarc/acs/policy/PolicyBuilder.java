package de.upb.crypto.clarc.acs.policy;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import org.apache.commons.lang3.Validate;

public class PolicyBuilder {
    /**
     * Inits the fluent description of an policy
     *
     * @param pp The {@link PublicParameters} to which the policy is subject to
     * @return -
     */
    public static PolicyFragment policy(PublicParameters pp, boolean isMasterCredentialRequired) {
        Validate.notNull(pp, "pp should not be null");
        return new PolicyFragment(new PolicyBuildingContext(pp, isMasterCredentialRequired));
    }

    /**
     * Inits the fluent description of an policy
     *
     * @param pp The {@link PublicParameters} to which the policy is subject to
     * @return -
     */
    public static PolicyFragment policy(PublicParameters pp) {
        Validate.notNull(pp, "pp should not be null");
        return new PolicyFragment(new PolicyBuildingContext(pp, false));
    }
}
