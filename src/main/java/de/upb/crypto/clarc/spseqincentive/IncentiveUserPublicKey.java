package de.upb.crypto.clarc.spseqincentive;

import de.upb.crypto.math.interfaces.structures.GroupElement;

public class IncentiveUserPublicKey {
	GroupElement upk;

	public IncentiveUserPublicKey(GroupElement upk) {
		this.upk = upk;
	}
}
