package de.upb.crypto.clarc.acs.systemmanager;

import de.upb.crypto.craco.interfaces.PublicParameters;

public interface SystemManagerKeyPairFactory {
    SystemManagerKeyPair create(PublicParameters pp);
}
