package de.upb.crypto.clarc.acs.issuer.impl.clarc.reviewtokens;

import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.craco.interfaces.PublicParameters;

public class ReviewTokenIssuerKeyPairFactory {
    private final PublicParameters pp;

    public ReviewTokenIssuerKeyPairFactory(PublicParameters pp) {
        this.pp = pp;
    }

    IssuerKeyPair create() {
        IssuerKeyPairFactory issuerKeyPairFactory = new IssuerKeyPairFactory();
        return issuerKeyPairFactory.create(pp, 1);
    }
}
