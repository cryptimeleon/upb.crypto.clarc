package de.upb.crypto.clarc.acs;

import de.upb.crypto.clarc.acs.issuer.credentials.IssuerKeyPair;
import de.upb.crypto.clarc.acs.issuer.impl.clarc.credentials.IssuerKeyPairFactory;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class FactorySmokeTest {
    @Test
    void factoriesSmokeTest() {
        PublicParametersFactory ppFactory = new PublicParametersFactory();
        ppFactory.setDebugMode(true);
        final PublicParameters pp = ppFactory.create();
        assertNotNull(pp, "pp");

        de.upb.crypto.clarc.acs.issuer.credentials.IssuerKeyPairFactory issuerKeyFactory = new IssuerKeyPairFactory();
        final IssuerKeyPair issuerKeyPair = issuerKeyFactory.create(pp, 2);
        assertNotNull(issuerKeyPair, "issuerKeyPair");
    }

}
