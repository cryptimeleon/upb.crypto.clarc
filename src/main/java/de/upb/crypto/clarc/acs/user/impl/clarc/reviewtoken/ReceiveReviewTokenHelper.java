package de.upb.crypto.clarc.acs.user.impl.clarc.reviewtoken;

import de.upb.crypto.clarc.acs.issuer.IssueResponse;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerPublicIdentity;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.RepresentableReviewToken;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens.ReviewToken;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserSecret;
import de.upb.crypto.craco.commitment.pedersen.PedersenOpenValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.interfaces.signature.VerificationKey;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.ArrayList;

public class ReceiveReviewTokenHelper {
    public static RepresentableReviewToken unblindReviewToken(PublicParameters pp,
                                                              IssueResponse<RepresentableReviewToken>
                                                                      issueResponse,
                                                              PedersenOpenValue openValue,
                                                              HashOfItem issuable,
                                                              UserSecret usk,
                                                              IssuerPublicIdentity issuerPublicIdentity) {
        ReviewToken reviewToken = issueResponse.getIssuedObject().getReviewToken(pp);
        final PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        PSSignature psSignature = reviewToken.getSignature();

        final PSSignature unblindedSignature =
                signatureScheme.unblindSignature(psSignature, openValue.getRandomValue());
        ReviewToken unblindedToken = new ReviewToken(
                unblindedSignature,
                reviewToken.getItem(),
                reviewToken.getRatingIssuerPublicKey());

        Zp.ZpElement hash = issuable.getHash();

        VerificationKey issuerPK = signatureScheme.getVerificationKey(issuerPublicIdentity.getIssuerPublicKey());

        final ArrayList<RingElementPlainText> plainText = new ArrayList<>();
        plainText.add(new RingElementPlainText(usk.getUsk()));
        plainText.add(new RingElementPlainText(hash));
        if (!signatureScheme.verify(new MessageBlock(plainText), unblindedSignature, issuerPK)) {
            throw new IllegalStateException("received non-matching signature on reviewToken");
        }
        return new RepresentableReviewToken(unblindedToken);
    }
}
