package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocol;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofProtocolFactory;
import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParameters;
import de.upb.crypto.craco.accumulators.nguyen.NguyenAccumulatorPublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentPair;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentScheme;
import de.upb.crypto.craco.commitment.pedersen.PedersenCommitmentSchemePublicParametersGen;
import de.upb.crypto.craco.commitment.pedersen.PedersenPublicParameters;
import de.upb.crypto.craco.common.RingElementPlainText;
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

		System.out.println("Token updated by " + k + " Points! New Balance: " + updatedToken.value);
		/* ----------- */


		/* Spend / Deduct */
		Zp.ZpElement k1 = zp.valueOf(25);
		DeductInstance deductInstance = provider.initDeduct(k1, dsid);
		SpendInstance spendInstance = user.initSpend(providerPublicKey, k1, dsid, deductInstance.gamma, updatedToken);

		Announcement[] schnorrAnnoucements = spendInstance.generateSchnorrAnnoucements();
		Announcement[] rangeAnnoucements = spendInstance.generateRangeAnnoucements();

		deductInstance.initProtocol(spendInstance.commitment, spendInstance.commitmentOnValue.getCommitmentValue(), spendInstance.c, spendInstance.ctrace, spendInstance.randToken, schnorrAnnoucements, (ArbitraryRangeProofPublicParameters) spendInstance.rangeProtocol.getPublicParameters(), rangeAnnoucements);

		deductInstance.chooseChallenge();
		DeductOutput deduct = deductInstance.deduct(spendInstance.generateSchnorrResponses(deductInstance.schnorrChallenge), spendInstance.generateRangeResponses(deductInstance.rangeChallenge));

		TokenDoubleSpendIdPair spend = spendInstance.spend(deduct.issuedSignature);

		System.out.println("New Balance: " + spend.token.value);

	}
}
