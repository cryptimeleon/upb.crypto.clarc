package de.upb.crypto.clarc.predicategeneration.fixedprotocols;

/**
 * Description for the different types of predicates whose fulfillment can be proven during a protocol execution.
 */
public enum PredicateTypePrimitive {
    EQUALITY_DLOG, EQUALITY_PUBLIC_VALUE, EQUALITY_2_ATTRIBUTES,
    INEQUALITY_DLOG, INEQUALITY_PUBLIC_VALUE, INEQUALITY_2_ATTRIBUTES,
    SET_MEMBERSHIP_ATTRIBUTE, ATTRIBUTE_IN_RANGE;


    public String getStringForElement(PredicateTypePrimitive comparator) {
        switch (comparator) {
            case EQUALITY_DLOG:
                return "equalityDLog";
            case EQUALITY_PUBLIC_VALUE:
                return "equalityPublicValue";
            case EQUALITY_2_ATTRIBUTES:
                return "equality2attributes";
            case INEQUALITY_DLOG:
                return "inequalityDLog";
            case INEQUALITY_PUBLIC_VALUE:
                return "inequalityPublicValue";
            case INEQUALITY_2_ATTRIBUTES:
                return "inequality2attributes";
            case SET_MEMBERSHIP_ATTRIBUTE:
                return "setMembership";
            case ATTRIBUTE_IN_RANGE:
                return "inRange";
            default:
                throw new IllegalArgumentException("Element must be contained in enum, " + comparator.toString() +
                        "is not contained");
        }
    }
}

