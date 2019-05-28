package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveProviderPublicKey {
    PSVerificationKey psVerificationKey;
    SPSEQVerificationKey spseqVerificationKey;
    GroupElement[] h1to6;

    public IncentiveProviderPublicKey(PSVerificationKey psVerificationKey, SPSEQVerificationKey spseqVerificationKey, GroupElement[] h1to6) {
        this.psVerificationKey = psVerificationKey;
        this.spseqVerificationKey = spseqVerificationKey;
        this.h1to6 = h1to6;
    }
}
