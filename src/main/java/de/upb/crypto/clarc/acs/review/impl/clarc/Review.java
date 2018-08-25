package de.upb.crypto.clarc.acs.review.impl.clarc;

import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.protocols.fiatshamirtechnique.impl.FiatShamirSignature;
import de.upb.crypto.craco.enc.sym.streaming.aes.ByteArrayImplementation;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * This is the Clarc implementation of a review.
 */
public class Review implements de.upb.crypto.clarc.acs.review.Review {
    @Represented
    private ByteArrayImplementation message;
    @Represented
    private Item item;
    private PSExtendedVerificationKey systemManagerPublicKey;
    private GroupElement linkabilityBasis;
    private PSExtendedVerificationKey raterPublicKey;
    private PSSignature blindedRegistrationInformation;
    private PSSignature blindedTokenSignature;
    private FiatShamirSignature ratingSignature;
    private GroupElement L1;
    private GroupElement L2;

    /**
     * Initializes the review with all needed parameters for linking and verifying.
     *
     * @param message                        Actual message of the review
     * @param item                           Item the review was created for
     * @param systemManagerPublicKey         Public key of the system Manager
     * @param linkabilityBasis               Group element used for every rating to link them
     * @param raterPublicKey                 Public key of ReviewVerifier
     * @param blindedRegistrationInformation Credential obtained after joining the system (blinded)
     * @param blindedTokenSignature          Signature obtained from token issuing/receiving protocol (blinded)
     * @param ratingSignature                Signature obtained from rate algorithm
     * @param L1                             Group element used in the rate algorithm together with hash of item
     * @param L2                             Group element used in the rate algorithm together with linking basis
     */
    public Review(ByteArrayImplementation message,
                  Item item,
                  PSExtendedVerificationKey systemManagerPublicKey,
                  GroupElement linkabilityBasis,
                  PSExtendedVerificationKey raterPublicKey,
                  PSSignature blindedRegistrationInformation,
                  PSSignature blindedTokenSignature,
                  FiatShamirSignature ratingSignature,
                  GroupElement L1,
                  GroupElement L2) {
        this.message = message;
        this.item = item;
        this.systemManagerPublicKey = systemManagerPublicKey;
        this.linkabilityBasis = linkabilityBasis;
        this.raterPublicKey = raterPublicKey;
        this.blindedRegistrationInformation = blindedRegistrationInformation;
        this.blindedTokenSignature = blindedTokenSignature;
        this.ratingSignature = ratingSignature;
        this.L1 = L1;
        this.L2 = L2;
    }

    public Review(Representation representation, de.upb.crypto.craco.interfaces.PublicParameters pp) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        PublicParameters clarcPP = (PublicParameters) pp;
        Group g1 = clarcPP.getBilinearMap().getG1();
        Group g2 = clarcPP.getBilinearMap().getG2();
        systemManagerPublicKey = new PSExtendedVerificationKey(g1, g2, representation.obj().get("systemManagerPublicKey"));
        linkabilityBasis = g2.getElement(representation.obj().get("linkabilityBasis"));
        raterPublicKey = new PSExtendedVerificationKey(g1, g2, representation.obj().get("raterPublicKey"));
        blindedRegistrationInformation =
                new PSSignature(representation.obj().get("blindedRegistrationInformation"), g1);
        blindedTokenSignature = new PSSignature(representation.obj().get("blindedTokenSignature"), g1);
        ratingSignature = new FiatShamirSignature(representation.obj().get("ratingSignature"));
        L1 = g1.getElement(representation.obj().get("L1"));
        L2 = g2.getElement(representation.obj().get("L2"));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        object.put("systemManagerPublicKey", systemManagerPublicKey.getRepresentation());
        object.put("linkabilityBasis", linkabilityBasis.getRepresentation());
        object.put("raterPublicKey", raterPublicKey.getRepresentation());
        object.put("blindedRegistrationInformation", blindedRegistrationInformation.getRepresentation());
        object.put("blindedTokenSignature", blindedTokenSignature.getRepresentation());
        object.put("ratingSignature", ratingSignature.getRepresentation());
        object.put("L1", L1.getRepresentation());
        object.put("L2", L2.getRepresentation());
        return object;
    }

    public ByteArrayImplementation getMessage() {
        return message;
    }

    public Item getItem() {
        return item;
    }

    public PSExtendedVerificationKey getSystemManagerPublicKey() {
        return systemManagerPublicKey;
    }

    public GroupElement getLinkabilityBasis() {
        return linkabilityBasis;
    }

    public PSExtendedVerificationKey getRaterPublicKey() {
        return raterPublicKey;
    }

    public PSSignature getBlindedRegistrationInformation() {
        return blindedRegistrationInformation;
    }

    public PSSignature getBlindedTokenSignature() {
        return blindedTokenSignature;
    }

    public FiatShamirSignature getRatingSignature() {
        return ratingSignature;
    }

    public GroupElement getL1() {
        return L1;
    }

    public GroupElement getL2() {
        return L2;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Review that = (Review) o;
        return Objects.equals(message, that.message) &&
                Objects.equals(item, that.item) &&
                Objects.equals(systemManagerPublicKey, that.systemManagerPublicKey) &&
                Objects.equals(linkabilityBasis, that.linkabilityBasis) &&
                Objects.equals(raterPublicKey, that.raterPublicKey) &&
                Objects.equals(blindedRegistrationInformation, that.blindedRegistrationInformation) &&
                Objects.equals(blindedTokenSignature, that.blindedTokenSignature) &&
                Objects.equals(ratingSignature, that.ratingSignature) &&
                Objects.equals(L1, that.L1) &&
                Objects.equals(L2, that.L2);
    }

    @Override
    public int hashCode() {
        return Objects
                .hash(message, item, systemManagerPublicKey, linkabilityBasis, raterPublicKey,
                        blindedRegistrationInformation, blindedTokenSignature, ratingSignature, L1, L2);
    }
}
