package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class Provider {
	IncentiveSystemPublicParameters pp;
	ProviderKeyPair keys;

	public Provider(IncentiveSystemPublicParameters pp) {
		this.pp = pp;
		ProviderSetup providerSetup = new ProviderSetup();
		this.keys = providerSetup.generateProviderKeys(pp);
	}

	public IssueInstance initIssue(IncentiveUserPublicKey userPublicKey, PedersenCommitmentValue c, Announcement[] announcements) {
		SigmaProtocol protocol = ZKAKProvider.getIssueReceiveVerifierProtocol(pp, new Zp(pp.group.getG1().size()), userPublicKey, keys.providerPublicKey, c);

		return new IssueInstance(pp, keys.providerPublicKey, keys.providerSecretKey, userPublicKey, c, protocol, announcements);
	}

	public CreditInstance initCredit(Zp.ZpElement k, PSSignature randToken, Announcement[] announcements) {
		return new CreditInstance(pp, keys.providerPublicKey, keys.providerSecretKey, k, randToken, ZKAKProvider.getCreditEarnVerifierProtocol(pp, randToken, keys.providerPublicKey), announcements);
	}

	public DeductInstance initDeduct(Zp.ZpElement k, GroupElement dsid) {
		Zp zp = new Zp(pp.group.getG1().size());

		Zp.ZpElement gamma = zp.getUniformlyRandomElement();

		return new DeductInstance(pp, keys.providerPublicKey, keys.providerSecretKey, k, dsid, gamma);

	}

}

