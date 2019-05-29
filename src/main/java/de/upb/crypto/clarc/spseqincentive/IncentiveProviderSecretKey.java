package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveProviderSecretKey {
    PSSigningKey psSigningKey;
    SPSEQSigningKey spseqSigningKey;
    Zp.ZpElement[] q;

    public IncentiveProviderSecretKey(PSSigningKey psSigningKey, SPSEQSigningKey spseqSigningKey, Zp.ZpElement[] q) {
        this.psSigningKey = psSigningKey;
        this.spseqSigningKey = spseqSigningKey;
        this.q = q;
    }
}
