package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.craco.sig.ps.PSVerificationKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQPublicParameters;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSigningKey;
import de.upb.crypto.craco.sig.sps.eq.SPSEQVerificationKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.List;

public class IncentiveProviderPublicKey {
    PSVerificationKey psVerificationKey;
    SPSEQVerificationKey spseqVerificationKey;
    SPSEQPublicParameters spseqPublicParameters;
    GroupElement[] h1to6;
    GroupElement digitsig_public_x, digitsig_public_y, digitsig_g2;
    List<GroupElement> digitsig_sigma_on_i;
    List<GroupElement> digitsig_h_on_i;

    public IncentiveProviderPublicKey(PSVerificationKey psVerificationKey, SPSEQVerificationKey spseqVerificationKey, SPSEQPublicParameters spseqPublicParameters, GroupElement[] h1to6, GroupElement digitsig_public_x, GroupElement digitsig_public_y, List<GroupElement> digitsig_sigma_on_i, List<GroupElement> digitsig_h_on_i, GroupElement digitsig_g2) {
        this.psVerificationKey = psVerificationKey;
        this.spseqVerificationKey = spseqVerificationKey;
        this.spseqPublicParameters = spseqPublicParameters;
        this.h1to6 = h1to6;
        this.digitsig_public_x = digitsig_public_x;
        this.digitsig_public_y = digitsig_public_y;
        this.digitsig_sigma_on_i = digitsig_sigma_on_i;
        this.digitsig_h_on_i = digitsig_h_on_i;
        this.digitsig_g2 = digitsig_g2;
    }
}
