package de.upb.crypto.clarc.incentive;

import de.upb.crypto.craco.sig.ps.PSExtendedVerificationKey;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.ps.PSSigningKey;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;

public class IncentiveSystem {

	public static void main(String[] args) {
		IncentiveSystemSetup setup = new IncentiveSystemSetup();
		IncentiveSystemPublicParameters pp = setup.generatePublicParameter(80);

		User user = new User(pp);
		IncentiveUserPublicKey userPublicKey = user.keyPair.userPublicKey;
		IncentiveUserSecretKey userSecretKey = user.keyPair.userSecretKey;

		Provider provider = new Provider(pp);
		PSExtendedVerificationKey providerPublicKey = provider.keys.providerPublicKey;
		PSSigningKey providerSecretKey = provider.keys.providerSecretKey;

		/* Issue / Receive */
		// assumption: exchange common input before-hand
		ReceiveInstance receiveInstance = user.initReceive(providerPublicKey);
		// --> upk
		// --> c
		// --> announcement
		IssueInstance issueInstance = provider.initIssue(userPublicKey, receiveInstance.c, receiveInstance.generateAnnoucements());

		// <-- ch
		// --> responses
		// <-- signature
		PSSignature blindedSignature = issueInstance.issue(receiveInstance.computeResponses(issueInstance.chooseChallenge()));
		TokenDoubleSpendIdPair output = receiveInstance.receive(blindedSignature);

		IncentiveToken token = output.token;
		GroupElement dsid = output.doubleSpendID;


		System.out.println("Token received!");

		/* ----------- */

		/* Credit / Earn */
		// value k  credited known to both parties
		Zp zp = new Zp(pp.group.getG1().size());
		Zp.ZpElement k = zp.valueOf(100);
		EarnInstance earnInstance = user.initEarn(providerPublicKey, k, token);
		// --> randToken
		// --> annoucement
		CreditInstance creditInstance = provider.initCredit(k, earnInstance.randToken, earnInstance.generateAnnoucements());
		// <-- ch
		// --> responses
		// <-- signature
		PSSignature blindedSig = creditInstance.credit(earnInstance.generateResponses(creditInstance.chooseChallenge()));
		IncentiveToken updatedToken = earnInstance.earn(blindedSig);

		System.out.println("Token updated by " + k + " Points!");
		/* ----------- */


		/* Spend / Deduct */
		Zp.ZpElement kPrime = zp.valueOf(50);
		DeductInstance deductInstance = provider.initDeduct(kPrime, dsid);

		SpendInstance spendInstance = user.initSpend(providerPublicKey, kPrime, dsid, deductInstance.gamma, updatedToken);

		deductInstance.initProtocol(spendInstance.commitment, spendInstance.commitmentOnValue.getCommitmentValue(), spendInstance.c, spendInstance.ctrace, spendInstance.randToken, spendInstance.generateAnnoucements());

		DeductOutput deduct = deductInstance.deduct(spendInstance.generateResponses(deductInstance.chooseChallenge()));

		TokenDoubleSpendIdPair spend = spendInstance.spend(deduct.issuedSignature);

		IncentiveToken tokenAfterSpend = spend.token;
		GroupElement dsidAfterSpend = spend.doubleSpendID;

		System.out.println("50 Points spend! New balance: " + tokenAfterSpend.value);
	}
}
