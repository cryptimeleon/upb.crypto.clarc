package de.upb.crypto.clarc.acs.policy;

public class AttributeFragment {
    private final IssuerScopedFragment fragment;
    private final String attributeName;

    AttributeFragment(IssuerScopedFragment fragment, String attributeName, boolean disclose) {
        this.fragment = fragment;
        this.attributeName = attributeName;
        if (disclose) {
            fragment.addDisclosedAttribute(attributeName);
        }
    }

    /**
     * Asserts that the said attribute is equal to a value
     *
     * @param value the value to compare against
     * @return {@link IssuerScopedFragment} an issuer scoped fragment for adding further restrictions
     */
    public IssuerScopedFragment isEqual(String value) {
        fragment.addEqualityCheck(attributeName, value);
        return fragment;
    }

    /**
     * Asserts that the said attribute is not equal to the given string value
     *
     * @param value the value to which the attribute should not be equal to
     * @return {@link IssuerScopedFragment} an issuer scoped fragment for adding further restrictions
     */
    public IssuerScopedFragment isNot(String value) {
        fragment.addInequalityCheck(attributeName, value);
        return fragment;
    }

    /**
     * Asserts that the said attribute is within a given set
     *
     * @param values the set of values
     * @return {@link IssuerScopedFragment} an issuer scoped fragment for adding further restrictions
     */
    public IssuerScopedFragment isInSet(String... values) {
        fragment.addSetCheck(attributeName, values);
        return fragment;
    }

    /**
     * Asserts that the said attribute is within a given range
     *
     * @param lowerBound the lower bound of the range
     * @param upperBound the upper bound of the range
     * @return {@link IssuerScopedFragment} an issuer scoped fragment for adding further restrictions
     */
    public IssuerScopedFragment isInRange(long lowerBound, long upperBound) {
        fragment.addRangeCheck(attributeName, lowerBound, upperBound);
        return fragment;
    }
}
