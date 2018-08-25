package de.upb.crypto.clarc.acs.systemmanager.impl.clarc;

import de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParameters;
import de.upb.crypto.clarc.acs.user.impl.clarc.UserPublicKey;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.Representation;
import de.upb.crypto.math.structures.zn.Zp;

import java.util.List;

import static de.upb.crypto.clarc.acs.setup.impl.clarc.PublicParametersFactory.getSignatureScheme;

public class CreateSignatureHelper {
    public static PSSignature computeSignature(List<RegistrationEntry> registry,
                                               UserPublicKey userPublicKey,
                                               PublicParameters pp,
                                               SystemManagerKeyPair clarcSystemManagerKeyPair,
                                               Representation tau) {
        PSExtendedSignatureScheme signatureScheme = getSignatureScheme(pp);
        for (RegistrationEntry entry : registry) {
            if (entry.getUserPublicKey().equals(userPublicKey)) {
                return signatureScheme.getSignature(entry.getSignature());
            }
        }
        GroupElement tauElement = pp.getBilinearMap().getG2().getElement(tau);
        GroupElement upk = pp.getBilinearMap().getG1().getElement(userPublicKey.getUpk());
        GroupElement g = clarcSystemManagerKeyPair.getPublicIdentity().getOpk().getGroup1ElementG();
        Zp zp = pp.getZp();
        Zp.ZpElement u = zp.getUniformlyRandomUnit();
        GroupElement g_u = g.pow(u);
        Zp.ZpElement x = clarcSystemManagerKeyPair.getSystemManagerSecretKey().getExponentX();
        Zp.ZpElement y = clarcSystemManagerKeyPair.getSystemManagerSecretKey().getExponentsYi()[0];
        GroupElement g_pow_x = g.pow(x);
        GroupElement upk_pow_y = upk.pow(y);
        PSSignature signature = new PSSignature(g_u, (g_pow_x.op(upk_pow_y)).pow(u));
        registry.add(new RegistrationEntry(userPublicKey, signature, tauElement));
        return signature;
    }
}
