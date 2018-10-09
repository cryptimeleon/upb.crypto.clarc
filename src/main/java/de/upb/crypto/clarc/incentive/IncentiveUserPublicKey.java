package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.interfaces.structures.GroupElement;

public class IncentiveUserPublicKey {
	GroupElement upk;

	public IncentiveUserPublicKey(GroupElement upk) {
		this.upk = upk;
	}
}
