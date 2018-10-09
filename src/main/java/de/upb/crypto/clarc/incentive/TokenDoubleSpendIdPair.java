package de.upb.crypto.clarc.incentive;

import de.upb.crypto.math.interfaces.structures.GroupElement;

public class TokenDoubleSpendIdPair {
	IncentiveToken token;
	GroupElement doubleSpendID;

	public TokenDoubleSpendIdPair(IncentiveToken token, GroupElement doubleSpendID) {
		this.token = token;
		this.doubleSpendID = doubleSpendID;
	}

	public IncentiveToken getToken() {
		return token;
	}

	public GroupElement getDoubleSpendID() {
		return doubleSpendID;
	}
}
