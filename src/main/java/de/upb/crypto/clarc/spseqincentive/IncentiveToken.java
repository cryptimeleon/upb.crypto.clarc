package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.sps.eq.SPSEQSignature;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveToken {
	Zp.ZpElement esk, dsrnd0, dsrnd1, z,t, value;
	MessageBlock M;
	SPSEQSignature token;

	public IncentiveToken(MessageBlock M, Zp.ZpElement esk, Zp.ZpElement dsrnd0, Zp.ZpElement dsrnd1, Zp.ZpElement z, Zp.ZpElement t, Zp.ZpElement value, SPSEQSignature token) {
		this.M = M;
		this.esk = esk;
		this.dsrnd0 = dsrnd0;
		this.dsrnd1 = dsrnd1;
		this.z = z;
		this.t = t;
		this.value = value;
		this.token = token;
	}
}
