package de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.interfaces.policy.ThresholdPolicy;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.structures.zn.Zp;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Objects;

/**
 * {@link Response} for the {@link ProofOfPartialKnowledgeProtocol} which contains the
 * ({@link Announcement}, {@link Challenge}, {@link Response})-tuple associated with a {@link SigmaProtocol} for a
 * leaf of the {@link ThresholdPolicy} to be proven.
 */
public class ProofOfPartialKnowledgeResponse implements Response {

    private SigmaProtocol protocol;
    @Represented
    private BigInteger protocolId;
    @RepresentedArray(elementRestorer = @Represented(structure = "protocol", recoveryMethod = Response.RECOVERY_METHOD))
    private Response[] responses;
    @Represented
    private Zp zp;
    @Represented(structure = "zp", recoveryMethod = Zp.ZpElement.RECOVERY_METHOD)
    private Zp.ZpElement challenge;

    public ProofOfPartialKnowledgeResponse(int protocolId, Response[] responses, Zp.ZpElement challenge) {
        this.protocolId = BigInteger.valueOf(protocolId);
        this.responses = responses;
        this.challenge = challenge;
        this.zp = challenge.getStructure();
    }

    public ProofOfPartialKnowledgeResponse(Representation representation, SigmaProtocol protocol) {
        this.protocol = protocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    public Response[] getResponses() {
        return responses;
    }

    public Zp getZp() {
        return zp;
    }

    public Zp.ZpElement getChallenge() {
        return challenge;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ProofOfPartialKnowledgeResponse that = (ProofOfPartialKnowledgeResponse) o;
        return Objects.equals(protocolId, that.protocolId) &&
                Arrays.equals(responses, that.responses) &&
                Objects.equals(zp, that.zp) &&
                Objects.equals(challenge, that.challenge);
    }

    @Override
    public int hashCode() {

        int result = Objects.hash(protocolId, zp, challenge);
        result = 31 * result + Arrays.hashCode(responses);
        return result;
    }
}
