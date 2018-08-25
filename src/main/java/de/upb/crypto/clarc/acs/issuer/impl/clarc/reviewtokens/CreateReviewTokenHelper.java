package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.HashOfItem;
import de.upb.crypto.clarc.acs.issuer.reviewtokens.Item;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.structures.zn.Zp;

public class CreateReviewTokenHelper {
    public static RepresentableReviewToken createBlindedReviewToken(
            PublicParameters pp,
            HashOfItem hashOfItem,
            IssuerKeyPair issuerKeyPair,
            PedersenCommitmentValue uskCommitValue) {
        final PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        final PSExtendedVerificationKey verificationKey = issuerKeyPair.getVerificationKey();

        Zp.ZpElement hash = hashOfItem.getHash();
        Item item = hashOfItem.getItem();

        final RingElementPlainText plainText = new RingElementPlainText(hash);

        final PSSignature signature = signatureScheme.blindSign(
                issuerKeyPair.getSigningKey(),
                verificationKey,
                uskCommitValue.getCommitmentElement(),
                new MessageBlock(plainText)
        );
        return new RepresentableReviewToken(new ReviewToken(
                signature,
                item,
                issuerKeyPair.getVerificationKey()));
    }
}
