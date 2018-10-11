package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.ArbitraryRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.pairings.debug.DebugBilinearMap;
import de.upb.crypto.math.pairings.debug.DebugGroupLogger;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class IncentiveSystemTest {
	IncentiveSystemPublicParameters pp;
	Zp zp;

	IncentiveUser user;
	IncentiveUserPublicKey userPK;
	IncentiveUserSecretKey userSK;

	IncentiveProvider provider;
	PSExtendedVerificationKey pk;
	PSSigningKey sk;

	PSExtendedSignatureScheme signatureScheme;

	static final int POINTS_CREDITED = 100;
	static final int POINTS_SPENT = 25;

	/* Performance parameter */
	protected long timerStart = 0;
	private int maxIterations = 1;

	@Before
	public void setup() {
		measureTime(null);
		IncentiveSystemSetup setup = new IncentiveSystemSetup();
		this.pp = setup.generatePublicParameter(80);
		measureTime("System setup");

		this.zp = new Zp(pp.group.getG1().size());

		// set up a single user
		measureTime(null);
		this.user = new IncentiveUser(pp);
		measureTime("User setup");
		this.userPK = user.keyPair.userPublicKey;
		this.userSK = user.keyPair.userSecretKey;

		// set up a single provider
		measureTime(null);
		this.provider = new IncentiveProvider(pp);
		measureTime("Provider setup");
		this.pk = provider.keyPair.providerPublicKey;
		this.sk = provider.keyPair.providerSecretKey;

		// set up signature scheme
		this.signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
	}

	@Test
	public void testIssueReceive() {
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendID;
		IncentiveToken userToken = output.token;

		// the balance after issuance should be 0
		assertEquals(userToken.value,zp.getZeroElement());

		// signature in token is valid on pk over usk, dldsig, dsrnd, value (of token)
		MessageBlock msg = new MessageBlock();
		Stream.of(userSK.usk, userToken.dldsid, userToken.dsrnd, userToken.value).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));
		assertTrue(signatureScheme.verify(msg, userToken.token, pk));

		// dsid =? w^dldsid
		assertEquals(userDoubleSpendID, pp.w.pow(userToken.dldsid));
	}

	@Test
	public void testCreditEarn() {
		// initialize a token
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendID;
		IncentiveToken userToken = output.token;

		IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken);

		// the balance after earn should be POINTS_CREDITED
		assertEquals(updatedToken.value,zp.valueOf(POINTS_CREDITED));

		// dldsid and dsrnd unchanged during credit
		assertEquals(userToken.dldsid, updatedToken.dldsid);
		assertEquals(userToken.dsrnd, updatedToken.dsrnd);

		// signature still valid?
		MessageBlock updatedMsg = new MessageBlock();
		Stream.of(userSK.usk, updatedToken.dldsid, updatedToken.dsrnd, updatedToken.value).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> updatedMsg));
		assertTrue(signatureScheme.verify(updatedMsg, updatedToken.token, pk));
	}

	@Test
	public void testSpendDeduct() {
		// initialize a token
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendID;
		IncentiveToken userToken = output.token;

		// credit POINTS_CREDITED many points
		IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken);

		TokenDoubleSpendIdPair spend = spendDeduct(zp, user, provider, pk, userDoubleSpendID, updatedToken);

		// double spend id different?
		assertNotEquals(userDoubleSpendID, spend.doubleSpendID);

		// balance updated?
		assertEquals(spend.token.value, updatedToken.value.sub(zp.valueOf(POINTS_SPENT)));
	}

	TokenDoubleSpendIdPair spendDeduct(Zp zp, IncentiveUser user, IncentiveProvider provider, PSExtendedVerificationKey pk, GroupElement userDoubleSpendID, IncentiveToken updatedToken) {
		// assumption: points k1 spent & double spend id known to both parties
		Zp.ZpElement k1 = zp.valueOf(POINTS_SPENT);
		DeductInstance deductInstance = provider.initDeduct(k1, userDoubleSpendID);
		// <-- gamma
		SpendInstance spendInstance = user.initSpend(pk, k1, userDoubleSpendID, deductInstance.gamma, updatedToken);

		Announcement[] schnorrAnnoucements = spendInstance.generateSchnorrAnnoucements();
		Announcement[] rangeAnnoucements = spendInstance.generateRangeAnnoucements();

		// --> C
		// --> C_v (commitment on v for range proof)
		// --> c
		// --> ctrace
		// --> randomized token
		// --> pp of the prover range proof protocol (ensure they use the same params)
		// --> annoucement1
		// --> annoucement2
		deductInstance.initProtocol(spendInstance.commitment, spendInstance.commitmentOnValue.getCommitmentValue(), spendInstance.c, spendInstance.ctrace, spendInstance.randToken, schnorrAnnoucements, (ArbitraryRangeProofPublicParameters) spendInstance.rangeProtocol.getPublicParameters(), rangeAnnoucements);

		deductInstance.chooseChallenge();
		// <-- ch
		// --> responses1
		// --> responses2
		// <-- blinded token signature
		DeductOutput deduct = deductInstance.deduct(spendInstance.generateSchnorrResponses(deductInstance.schnorrChallenge), spendInstance.generateRangeResponses(deductInstance.rangeChallenge));
		return spendInstance.spend(deduct.issuedSignature);
	}

	IncentiveToken creditEarn(Zp zp, IncentiveUser user, IncentiveProvider provider, PSExtendedVerificationKey pk, IncentiveToken userToken) {
		// asssumption: value k credited known to both parties
		Zp.ZpElement k = zp.valueOf(POINTS_CREDITED);
		EarnInstance earnInstance = user.initEarn(pk, k, userToken);
		// --> randToken
		// --> annoucement
		CreditInstance creditInstance = provider.initCredit(k, earnInstance.randToken, earnInstance.generateAnnoucements());
		// <-- ch
		// --> responses
		// <-- signature
		PSSignature blindedSig = creditInstance.credit(earnInstance.generateResponses(creditInstance.chooseChallenge()));
		return earnInstance.earn(blindedSig);
	}

	TokenDoubleSpendIdPair issueReceive(IncentiveUser user, IncentiveUserPublicKey userPK, IncentiveProvider provider, PSExtendedVerificationKey pk) {
		// assumption: exchange common input before-hand
		ReceiveInstance receiveInstance = user.initReceive(pk);
		// --> upk
		// --> c
		// --> announcement
		IssueInstance issueInstance = provider.initIssue(userPK, receiveInstance.c, receiveInstance.generateAnnoucements());

		// <-- ch
		// --> responses
		// <-- signature
		PSSignature blindedSignature = issueInstance.issue(receiveInstance.computeResponses(issueInstance.chooseChallenge()));
		return receiveInstance.receive(blindedSignature);
	}

	/* Performance tests */
	protected void measureTime(String str) {
		if (timerStart == 0) {
			DebugGroupLogger.reset();
			timerStart = System.currentTimeMillis();
		} else {
			long end = System.currentTimeMillis();
			System.out.println(str + ": " + ((end - timerStart) / 1000) + "s " + ((end - timerStart) % 1000) + "ms");
			if (pp.group.getBilinearMap() instanceof DebugBilinearMap)
				DebugGroupLogger.print();
			timerStart = 0;
		}
	}

	@Test
	public void evalIssueReceive() {
		for (int i = 0; i < maxIterations; i++) {
			measureTime(null);
			TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendID;
			IncentiveToken userToken = output.token;
			measureTime("Issue / Receive Token");
		}
	}

	@Test
	public void evalCreditEarn() {
		for (int i = 0; i < maxIterations; i++) {
			TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendID;
			IncentiveToken userToken = output.token;

			measureTime(null);
			IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken);
			measureTime("Credit / Earn");
		}
	}

	@Test
	public void evalSpendDeduct() {
		for (int i = 0; i < maxIterations; i++) {
			TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendID;
			IncentiveToken userToken = output.token;
			IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken);

			measureTime(null);
			TokenDoubleSpendIdPair spend = spendDeduct(zp, user, provider, pk, userDoubleSpendID, updatedToken);
			measureTime("Spend / Deduct");
		}
	}
}
