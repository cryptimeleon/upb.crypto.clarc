package de.upb.crypto.clarc.acs.subpolicyproving;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.*;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SubPolicyProvingProtocolAnnouncement implements Announcement {

    @Represented(structure = "psSignatureScheme", recoveryMethod = PSSignature.RECOVERY_METHOD)
    private PSSignature randomizedSignature;
    private PSExtendedSignatureScheme psSignatureScheme;

    @RepresentedList(elementRestorer = @Represented)
    private List<PedersenCommitmentValue> commitmentsOnAttributes;
    @RepresentedMap(keyRestorer = @Represented, valueRestorer = @Represented)
    private Map<Integer, AttributeNameValuePair> disclosedElements;

    @RepresentedArray(elementRestorer = @Represented(structure = "signatureProtocol", recoveryMethod = Announcement
            .RECOVERY_METHOD))
    private Announcement[] announcementsOfSignatureProtocol;
    @RepresentedArray(elementRestorer = @Represented(structure = "predicateProvingProtocol", recoveryMethod =
            Announcement.RECOVERY_METHOD))
    private Announcement[] announcementsOfPredicateProvingProtocol;

    private SigmaProtocol signatureProtocol;
    private SigmaProtocol predicateProvingProtocol;

    public SubPolicyProvingProtocolAnnouncement(PSSignature randomizedSignature,
                                                List<PedersenCommitmentValue> commitmentsOnAttributes,
                                                Map<Integer, AttributeNameValuePair> disclosedElements,
                                                Announcement[] announcementsOfPredicateProvingProtocol,
                                                Announcement[] announcementsOfSignatureProtocol) {
        this.randomizedSignature = randomizedSignature;
        this.commitmentsOnAttributes = commitmentsOnAttributes;
        this.disclosedElements = disclosedElements;
        this.announcementsOfPredicateProvingProtocol = announcementsOfPredicateProvingProtocol;
        this.announcementsOfSignatureProtocol = announcementsOfSignatureProtocol;
    }

    public SubPolicyProvingProtocolAnnouncement(Representation representation, SigmaProtocol signatureProtocol,
                                                SigmaProtocol predicateProvingProtocol,
                                                PSExtendedSignatureScheme psSignatureScheme) {
        this.signatureProtocol = signatureProtocol;
        this.predicateProvingProtocol = predicateProvingProtocol;
        this.psSignatureScheme = psSignatureScheme;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);

    }

    public Announcement[] getAnnouncementsOfSignatureProtocol() {
        return announcementsOfSignatureProtocol;
    }

    public void setAnnouncementsOfSignatureProtocol(Announcement[] announcementsOfSignatureProtocol) {
        this.announcementsOfSignatureProtocol = announcementsOfSignatureProtocol;
    }

    public PSSignature getRandomizedSignature() {
        return randomizedSignature;
    }

    public void setRandomizedSignature(PSSignature randomizedSignature) {
        this.randomizedSignature = randomizedSignature;
    }

    public Announcement[] getAnnouncementsOfPredicateProvingProtocol() {
        return announcementsOfPredicateProvingProtocol;
    }

    public Map<Integer, AttributeNameValuePair> getDisclosedElements() {
        return disclosedElements;
    }

    public void setDisclosedElements(
            Map<Integer, AttributeNameValuePair> disclosedElements) {
        this.disclosedElements = disclosedElements;
    }

    public List<PedersenCommitmentValue> getCommitmentsOnAttributes() {
        return commitmentsOnAttributes;
    }

    public void setCommitmentsOnAttributes(
            List<PedersenCommitmentValue> commitmentsOnAttributes) {
        this.commitmentsOnAttributes = commitmentsOnAttributes;
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        byteAccumulator.escapeAndSeparate(this.randomizedSignature.getGroup1ElementSigma1());
        byteAccumulator.escapeAndSeparate(this.randomizedSignature.getGroup1ElementSigma2());

        for (Announcement announcement : announcementsOfPredicateProvingProtocol) {
            byteAccumulator.escapeAndSeparate(announcement);
        }
        byteAccumulator.appendSeperator();
        for (Announcement announcement : this.announcementsOfSignatureProtocol) {
            byteAccumulator.escapeAndSeparate(announcement);
        }
        return byteAccumulator;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        SubPolicyProvingProtocolAnnouncement that = (SubPolicyProvingProtocolAnnouncement) o;
        return Objects.equals(getRandomizedSignature(), that.getRandomizedSignature()) &&
                Objects.equals(getCommitmentsOnAttributes(), that.getCommitmentsOnAttributes()) &&
                Objects.equals(getDisclosedElements(), that.getDisclosedElements()) &&
                Arrays.equals(getAnnouncementsOfSignatureProtocol(), that.getAnnouncementsOfSignatureProtocol()) &&
                Arrays.equals(getAnnouncementsOfPredicateProvingProtocol(),
                        that.getAnnouncementsOfPredicateProvingProtocol());
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(getRandomizedSignature(), getCommitmentsOnAttributes(), getDisclosedElements());
        result = 31 * result + Arrays.hashCode(getAnnouncementsOfSignatureProtocol());
        result = 31 * result + Arrays.hashCode(getAnnouncementsOfPredicateProvingProtocol());
        return result;
    }
}
