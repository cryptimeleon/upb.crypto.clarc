package de.upb.crypto.clarc.acs.protocols.impl.clarc.provecred;

import de.upb.crypto.clarc.acs.verifier.credentials.RepresentableSignature;
import de.upb.crypto.clarc.protocols.generalizedschnorrprotocol.GeneralizedSchnorrProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;
import de.upb.crypto.math.serialization.annotations.RepresentedArray;

import java.util.Arrays;

/**
 * This {@link Announcement} is specifically used during the execution of a {@link PolicyProvingWithMasterCredProtocol}.
 * It contains the {@link Announcement} of both inner protocol as well as the {@link DisclosedAttributes} disclosed by
 * the prover.
 */
public class PolicyProvingWithMasterCredAnnouncement implements Announcement {

    private PolicyProvingProtocol policyProvingProtocol;
    private GeneralizedSchnorrProtocol masterCredProvingProtocol;

    @RepresentedArray(elementRestorer = @Represented(structure = "policyProvingProtocol",
            recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] policyAnnouncements;
    @RepresentedArray(elementRestorer = @Represented(structure = "masterCredProvingProtocol",
            recoveryMethod = Announcement.RECOVERY_METHOD))
    private Announcement[] masterCredAnnouncements;
    @Represented
    private RepresentableSignature masterCred;

    public PolicyProvingWithMasterCredAnnouncement(
            Announcement[] policyAnnouncements,
            Announcement[] masterCredAnnouncements,
            RepresentableSignature masterCred) {
        this.policyAnnouncements = policyAnnouncements;
        this.masterCredAnnouncements = masterCredAnnouncements;
        this.masterCred = masterCred;
    }

    public PolicyProvingWithMasterCredAnnouncement(Representation representation,
                                                   PolicyProvingProtocol policyProvingProtocol,
                                                   GeneralizedSchnorrProtocol masterCredProvingProtocol) {
        this.policyProvingProtocol = policyProvingProtocol;
        this.masterCredProvingProtocol = masterCredProvingProtocol;
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
    }

    @Override
    public ByteAccumulator updateAccumulator(ByteAccumulator byteAccumulator) {
        for (Announcement announcement : policyAnnouncements) {
            byteAccumulator.escapeAndSeparate(announcement);
        }
        for (Announcement announcement : masterCredAnnouncements) {
            byteAccumulator.escapeAndSeparate(announcement);
        }
        return byteAccumulator;
    }

    public Announcement[] getPolicyAnnouncements() {
        return policyAnnouncements;
    }

    public Announcement[] getMasterCredAnnouncements() {
        return masterCredAnnouncements;
    }

    public RepresentableSignature getMasterCred() {
        return masterCred;
    }

    @Override
    public Representation getRepresentation() {
        return AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PolicyProvingWithMasterCredAnnouncement that = (PolicyProvingWithMasterCredAnnouncement) o;
        return Arrays.equals(policyAnnouncements, that.policyAnnouncements) &&
                Arrays.equals(masterCredAnnouncements, that.masterCredAnnouncements);
    }

    @Override
    public int hashCode() {
        int result = Arrays.hashCode(policyAnnouncements);
        result = 31 * result + Arrays.hashCode(masterCredAnnouncements);
        return result;
    }
}
