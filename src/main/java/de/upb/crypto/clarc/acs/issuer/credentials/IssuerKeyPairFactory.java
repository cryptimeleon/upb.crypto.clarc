package de.upb.crypto.clarc.acs.issuer.credentials;

import de.upb.crypto.craco.interfaces.PublicParameters;

public interface IssuerKeyPairFactory {
    IssuerKeyPair create(PublicParameters pp, int numberOfAttributes);
}
