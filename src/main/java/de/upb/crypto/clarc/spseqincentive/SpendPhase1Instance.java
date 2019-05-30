package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.hashthensign.HashThenSign;
import de.upb.crypto.craco.interfaces.signature.Signature;
import de.upb.crypto.craco.interfaces.signature.SignatureScheme;
import de.upb.crypto.craco.sig.ps.PSExtendedSignatureScheme;
import de.upb.crypto.craco.sig.ps.PSPublicParameters;
import de.upb.crypto.math.hash.impl.ByteArrayAccumulator;
import de.upb.crypto.math.hash.impl.VariableOutputLengthHashFunction;
import de.upb.crypto.math.interfaces.hash.ByteAccumulator;
import de.upb.crypto.math.interfaces.hash.HashFunction;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.structures.zn.Zp;

public class SpendPhase1Instance extends CPreComProofInstance {

    Zp.ZpElement gamma;
    Zp.ZpElement tid;
    IncentiveToken token;
    Zp.ZpElement k;

    public SpendPhase1Instance(IncentiveSystemPublicParameters pp, IncentiveProviderPublicKey pk, IncentiveUserKeyPair keyPair, Zp.ZpElement k, IncentiveToken token, IncentiveUser.CPreComProofValues cPreComProofValues) {
        super(pp, pk, keyPair, cPreComProofValues);
        this.token = token;
        this.k = k;
    }


    /** Initializes the ZKAK protocol after receiving the eskisr of the issuer.
     *
     * @param eskisr
     *          issuer's (random) esk share
     */
    public void initProtocol(Zp.ZpElement eskisr, Zp.ZpElement gamma, Zp.ZpElement tid) {
        Group groupG1 = pp.group.getG1();
        Zp zp = new Zp(groupG1.size());

        this.eskisr = eskisr;
        this.gamma = gamma;
        this.tid = tid;

        //  use cPre
        open = zp.getUniformlyRandomElement();

        bCom = pk.h1to6[0].pow(usrKeypair.userSecretKey.usk).op(pp.g1.pow(open));

        this.protocol = ZKAKProvider.getSpendPhase1ProverProtocol(pp, zp, this);
    }


    /**
     * Checks the digital signature (for later recovery) and updates the esk
     * @param signature
     * @return esk
     */
    public boolean endPhase1(Signature signature){
        PSExtendedSignatureScheme psScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));

        HashFunction hashFunction = new VariableOutputLengthHashFunction(psScheme
                .getMaxNumberOfBytesForMapToPlaintext());

        HashThenSign hashThenSign = new HashThenSign(hashFunction,psScheme);

        ByteArrayAccumulator byteAccumulator = new ByteArrayAccumulator();
        byteAccumulator.append(tid);
        byteAccumulator.append(pp.w.pow(token.esk));
        byteAccumulator.append(k);
        byteAccumulator.append(cPre);
        byteAccumulator.append(eskisr);
        byteAccumulator.append(gamma);

        boolean b = hashThenSign.verify(byteAccumulator, signature, pk.psVerificationKey);

        return b;
    }

}
