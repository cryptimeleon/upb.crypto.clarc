package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.craco.interfaces.PublicParameters;
import de.upb.crypto.craco.secretsharing.SecretSharingSchemeProvider;
import de.upb.crypto.craco.secretsharing.ThresholdTreeSecretSharing;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.Objects;

/**
 * {@link PublicParameters} of a {@link ProofOfPartialKnowledgeResponse} which contain the information needed to
 * uniquely construct the
 * {@link ThresholdTreeSecretSharing} instance used during the protocol execution.
 */
public class ProofOfPartialKnowledgePublicParameters implements PublicParameters {
    @Represented
    private SecretSharingSchemeProvider lsssProvider;
    @Represented
    private Zp zp;

    public ProofOfPartialKnowledgePublicParameters(SecretSharingSchemeProvider lsssProvider, Zp zp) {
        this.lsssProvider = lsssProvider;
        this.zp = zp;
    }

    public ProofOfPartialKnowledgePublicParameters(Representation representation) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public SecretSharingSchemeProvider getLsssProvider() {
        return lsssProvider;
    }

    public Zp getZp() {
        return zp;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProofOfPartialKnowledgePublicParameters that = (ProofOfPartialKnowledgePublicParameters) o;
        return Objects.equals(lsssProvider, that.lsssProvider) &&
                Objects.equals(zp, that.zp);
    }

    @Override
    public int hashCode() {

        return Objects.hash(lsssProvider, zp);
    }
}
