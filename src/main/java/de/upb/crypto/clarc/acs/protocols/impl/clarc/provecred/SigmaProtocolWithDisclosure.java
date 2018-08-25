package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;

import java.util.List;

/**
 * A special kind of {@link SigmaProtocol} which allows the verifier to demand certain {@link AttributeNameValuePair}
 * of the prover to be disclosed during protocol execution.
 * The verifier will be able to extract the {@link DisclosedAttributes} after a successful protocol execution.
 */
public abstract class SigmaProtocolWithDisclosure extends SigmaProtocol {
    public abstract List<DisclosedAttributes> getDisclosedAttributes();
}
