package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.acs.pseudonym.Pseudonym;
import de.upb.crypto.math.serialization.StandaloneRepresentable;

/**
 * ProtocolParameters define the common input needed by all participants during the protocol execution.
 */
public interface ProtocolParameters extends StandaloneRepresentable {
    /**
     * @return prover's pseudonym used during the protocol execution
     */
    Pseudonym getPseudonym();
}
