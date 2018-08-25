package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.pseudonym.impl.clarc.Pseudonym;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.SecretSharingSchemeProviders;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.craco.interfaces.policy.Policy;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * Public {@link de.upb.crypto.clarc.acs.protocols.ProtocolParameters} which are needed for protocols proving the fulfillment of a {@link Policy} using
 * {@link PSCredential}.
 * <p>
 * It contains the prover's {@link de.upb.crypto.clarc.acs.pseudonym.Pseudonym} used during interaction with the
 * verifier as well as the {@link SecretSharingSchemeProvider} used for the internal proofs of partial knowledge.
 * <p>
 * (see {@link ProofOfPartialKnowledgeProtocol})
 */
public class ProtocolParameters implements de.upb.crypto.clarc.acs.protocols.ProtocolParameters {
    @Represented
    private Pseudonym clarcPseudonym;
    @Represented
    private SecretSharingSchemeProvider lsssProvider;


    public ProtocolParameters(Pseudonym clarcPseudonym) {
        this(clarcPseudonym, SecretSharingSchemeProviders.SHAMIR);
    }

    public ProtocolParameters(Pseudonym clarcPseudonym,
                              SecretSharingSchemeProvider lsssProvider) {
        this.clarcPseudonym = clarcPseudonym;
        this.lsssProvider = lsssProvider;
    }


    public ProtocolParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }


    @Override
    public Pseudonym getPseudonym() {
        return clarcPseudonym;
    }

    public SecretSharingSchemeProvider getLsssProvider() {
        return lsssProvider;
    }


    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProtocolParameters that = (ProtocolParameters) o;
        return Objects.equals(clarcPseudonym, that.clarcPseudonym) &&
                Objects.equals(lsssProvider, that.lsssProvider);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clarcPseudonym, lsssProvider);
    }
}
