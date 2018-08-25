package de.upb.crypto.clarc.acs.protocols;

import de.upb.crypto.clarc.protocols.arguments.InteractiveThreeWayAoK;

/**
 * The ProtocolFactory is responsible for creating the protocol instances of a interactive three-way argument of
 * knowledge.
 */
public interface ProtocolFactory {
    /**
     * Generates a protocol instance.
     *
     * @return The {@link InteractiveThreeWayAoK} protocol object
     */
    InteractiveThreeWayAoK getProtocol();
}
