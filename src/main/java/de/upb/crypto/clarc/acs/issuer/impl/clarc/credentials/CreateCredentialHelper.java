package de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.clarc.acs.issuer.credentials.Attributes;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import de.upb.crypto.clarc.acs.user.credentials.PSCredential;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

/**
 * This is a simple helper class providing a static method which creates the blinded credential. This is used
 * during the protocol by the Issuer.
 */
class CreateCredentialHelper {
    public static PSCredential createBlindedCredential(PublicParameters pp,
                                                       Attributes attributes,
                                                       IssuerKeyPair issuerKeyPair,
                                                       CredentialIssuerPublicIdentity issuerPublicIdentity,
                                                       PedersenCommitmentValue uskCommitValue) {

        final PSExtendedSignatureScheme signatureScheme = PublicParametersFactory.getSignatureScheme(pp);
        final PSExtendedVerificationKey verificationKey = issuerKeyPair.getVerificationKey();

        AttributeNameValuePair[] userAttributes = attributes.getAttributes(issuerPublicIdentity.getAttributeSpace());
        final List<RingElementPlainText> plainText = Arrays.stream(userAttributes)
                .map(attr -> attr.getZpRepresentation(pp.getHashIntoZp()))
                .map(RingElementPlainText::new)
                .collect(Collectors.toList());

        final PSSignature signature = signatureScheme.blindSign(
                issuerKeyPair.getSigningKey(),
                verificationKey,
                uskCommitValue.getCommitmentElement(),
                new MessageBlock(plainText)
        );
        return new PSCredential(signature.getRepresentation(), userAttributes, verificationKey.getRepresentation());
    }
}
