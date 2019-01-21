package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.interfaces.structures.GroupElement;

public class TokenDoubleSpendIdPair {
	IncentiveToken token;
	GroupElement doubleSpendIDinGroup;

	public TokenDoubleSpendIdPair(IncentiveToken token, GroupElement doubleSpendIDinGroup) {
		this.token = token;
		this.doubleSpendIDinGroup = doubleSpendIDinGroup;
	}

	public IncentiveToken getToken() {
		return token;
	}

	public GroupElement getDoubleSpendIDinGroup() {
		return doubleSpendIDinGroup;
	}
}
