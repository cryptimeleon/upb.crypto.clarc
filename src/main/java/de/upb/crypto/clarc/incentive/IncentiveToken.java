package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveToken {
	Zp.ZpElement dsid, dsrnd, value;
	PSSignature token;

	public IncentiveToken(Zp.ZpElement dsid, Zp.ZpElement dsrnd, Zp.ZpElement value, PSSignature token) {
		this.dsid = dsid;
		this.dsrnd = dsrnd;
		this.value = value;
		this.token = token;
	}
}
