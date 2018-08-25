package de.upb.crypto.clarc.acs.user.credentials;

import de.upb.crypto.clarc.acs.attributes.AttributeNameValuePair;
import de.upb.crypto.math.serialization.Representation;


public class PSCredential extends SignatureCredential {

    public PSCredential(Representation signatureRepresentation, AttributeNameValuePair[] attributes,
                        Representation issuerPublicKeyRepresentation) {
        super(signatureRepresentation, attributes, issuerPublicKeyRepresentation);
    }

    public PSCredential(Representation representation) {
        super(representation);
    }
}
