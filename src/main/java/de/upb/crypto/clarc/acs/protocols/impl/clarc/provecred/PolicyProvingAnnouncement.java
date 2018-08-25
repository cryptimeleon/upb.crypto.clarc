package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.predicategeneration.fixedprotocols.popk.ProofOfPartialKnowledgeProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;
import de.upb.crypto.math.serialization.annotations.RepresentedList;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * This {@link Announcement} is specifically used during the execution of a {@link PolicyProvingProtocol}.
 * It contains the {@link Announcement} of the inner protocol as well as the {@link DisclosedAttributes} disclosed by
 * the prover.
 */
public class PolicyProvingAnnouncement implements Announcement {

    private ProofOfPartialKnowledgeProtocol popkProtocol;

    @RepresentedArray(elementRestorer = @Represented(structure = "popkProtocol",
            recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] popkAnnouncements;

    @RepresentedList(elementRestorer = @Represented)
    private List<DisclosedAttributes> disclosedAttributes;

    public PolicyProvingAnnouncement(Announcement[] popkAnnouncements,
                                     List<DisclosedAttributes> disclosedAttributes) {
        this.popkAnnouncements = popkAnnouncements;
        this.disclosedAttributes = disclosedAttributes;
    }

    public PolicyProvingAnnouncement(Representation representation, ProofOfPartialKnowledgeProtocol popkProtocol) {
        this.popkProtocol = popkProtocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        for (Announcement announcement : popkAnnouncements) {
            byteAccumulator.escapeAndSeparate(announcement);
        }
        byteAccumulator.appendSeperator();
        for (DisclosedAttributes disclosedAttribute : disclosedAttributes) {
            byteAccumulator.escapeAndSeparate(disclosedAttribute.getIssuerPublicKey().toString()); //TODO toString() is not ideal.
            for (AttributeNameValuePair attribute : disclosedAttribute.getAttributes()) {
                byteAccumulator.escapeAndSeparate(attribute.toString());
            }
            byteAccumulator.appendSeperator();
        }
        return byteAccumulator;
    }

    public Announcement[] getPopkAnnouncements() {
        return popkAnnouncements;
    }

    public List<DisclosedAttributes> getDisclosedAttributes() {
        return disclosedAttributes;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyProvingAnnouncement that = (PolicyProvingAnnouncement) o;
        return Arrays.equals(popkAnnouncements, that.popkAnnouncements) &&
                Objects.equals(disclosedAttributes, that.disclosedAttributes);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(disclosedAttributes);
        result = 31 * result + Arrays.hashCode(popkAnnouncements);
        return result;
    }
}
