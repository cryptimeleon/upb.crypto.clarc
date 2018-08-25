package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.serialization.annotations.AnnotatedRepresentationUtil;
import de.upb.crypto.math.serialization.annotations.Represented;

import java.util.Objects;

/**
 * This is the implementation of the reviewToken using {@link PSSignature}'s. This class is not
 * StandaloneRepresentable, this is solved by using the {@link RepresentableReviewToken}.
 */
public class ReviewToken implements de.upb.crypto.clarc.acs.issuer.reviewtokens.ReviewToken {
    private PSSignature signature;
    @Represented
    private Item item;
    private PSExtendedVerificationKey ratingIssuerPublicKey;

    public ReviewToken(PSSignature signature,
                       Item item,
                       PSExtendedVerificationKey ratingIssuerPublicKey) {
        this.signature = signature;
        this.item = item;
        this.ratingIssuerPublicKey = ratingIssuerPublicKey;
    }

    public ReviewToken(Representation representation, de.upb.crypto.craco.interfaces.PublicParameters pp) {
        AnnotatedRepresentationUtil.restoreAnnotatedRepresentation(representation, this);
        PublicParameters clarcPP = (PublicParameters) pp;
        Group g1 = clarcPP.getBilinearMap().getG1();
        Group g2 = clarcPP.getBilinearMap().getG2();
        signature = new PSSignature(representation.obj().get("signature"), g1);
        ratingIssuerPublicKey = new PSExtendedVerificationKey(g1, g2, representation.obj().get("ratingIssuerPublicKey"));
    }

    @Override
    public Representation getRepresentation() {
        ObjectRepresentation object = AnnotatedRepresentationUtil.putAnnotatedRepresentation(this);
        object.put("signature", signature.getRepresentation());
        object.put("ratingIssuerPublicKey", ratingIssuerPublicKey.getRepresentation());
        return object;
    }

    public PSSignature getSignature() {
        return signature;
    }

    public Item getItem() {
        return item;
    }

    public PSExtendedVerificationKey getRatingIssuerPublicKey() {
        return ratingIssuerPublicKey;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ReviewToken that = (ReviewToken) o;
        return Objects.equals(signature, that.signature) &&
                Objects.equals(item, that.item) &&
                Objects.equals(ratingIssuerPublicKey, that.ratingIssuerPublicKey);
    }

    @Override
    public int hashCode() {
        return Objects.hash(signature, item, ratingIssuerPublicKey);
    }
}
