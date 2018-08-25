package de.upb.crypto.clarc.acs.policy;

enum AggregationMethod {
    AND,
    OR;

    static int getThreshold(AggregationMethod aggregationMethod, int numberOfChilds) {
        if (aggregationMethod == null) {
            return numberOfChilds;
        }
        switch (aggregationMethod) {
            case OR:
                return 1;
            case AND:
                return numberOfChilds;
            default:
                throw new IllegalStateException("unexpected aggregation type " + aggregationMethod);
        }
    }
}
