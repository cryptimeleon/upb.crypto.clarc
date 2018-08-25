package de.upb.crypto.clarc.predicategeneration;

import de.upb.crypto.clarc.predicategeneration.policies.PredicatePolicyFact;
import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.math.interfaces.hash.UniqueByteRepresentable;

/**
 * Marker interface for {@link PublicParameters} to be used for a {@link PredicatePolicyFact} to be able to correctly
 * compute {@link UniqueByteRepresentable#getUniqueByteRepresentation} of the overall {@link Policy}
 */
public interface PredicatePublicParameters extends PublicParameters, UniqueByteRepresentable {
}
