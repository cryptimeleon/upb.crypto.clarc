package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentValue;
import de.upb.crypto.craco.enc.asym.elgamal.ElgamalCipherText;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.math.interfaces.structures.Group;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

/**
 * Represents the provider of the incentive system,
 * <p>
 * The main task is to set up the verifier instances of the protocols ran in the system.
 */
public class IncentiveProvider {
	IncentiveSystemPublicParameters pp;
	IncentiveProviderKeyPair keyPair;

	public IncentiveProvider(IncentiveSystemPublicParameters pp) {
		this.pp = pp;
		IncentiveProviderSetup providerSetup = new IncentiveProviderSetup();
		this.keyPair = providerSetup.generateProviderKeys(pp);
	}

	public IssueInstance initIssue(IncentiveUserPublicKey userPublicKey, ElgamalCipherText cUsr) {
		Group g1 = pp.group.getG1();
		Zp zp = new Zp(g1.size());

		// dsidIsr <- Zp
		Zp.ZpElement dsidIsr = zp.getUniformlyRandomElement();

		// C_Dsid = (g^open, g^{dsid_usr} * h^open * g^{dsid_isr}
		ElgamalCipherText cDsid = new ElgamalCipherText(cUsr.getC1(), cUsr.getC2().op(pp.g.pow(dsidIsr)));


		return new IssueInstance(pp, keyPair.providerPublicKey, keyPair.providerSecretKey, userPublicKey, dsidIsr, cDsid);
	}

	public CreditInstance initCredit(Zp.ZpElement k, PSSignature randToken, Announcement[] announcements) {
		return new CreditInstance(pp, keyPair.providerPublicKey, keyPair.providerSecretKey, k, randToken, ZKAKProvider.getCreditEarnVerifierProtocol(pp, randToken, keyPair.providerPublicKey), announcements);
	}

	public DeductInstance initDeduct(Zp.ZpElement k, Zp.ZpElement dsid, ElgamalCipherText cUsrStar) {
		Zp zp = new Zp(pp.group.getG1().size());

		Zp.ZpElement dsidIsrStar = zp.getUniformlyRandomElement();
		Zp.ZpElement gamma = zp.getUniformlyRandomElement();

		ElgamalCipherText cDsidStar = new ElgamalCipherText(cUsrStar.getC1(), cUsrStar.getC2().op(pp.g.pow(dsidIsrStar)));

		return new DeductInstance(pp, keyPair.providerPublicKey, keyPair.providerSecretKey, k, dsid, dsidIsrStar, gamma, cDsidStar);

	}

}

