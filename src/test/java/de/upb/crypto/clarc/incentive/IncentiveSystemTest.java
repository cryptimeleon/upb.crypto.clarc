package de.upb.crypto.clarc.incentive;

import de.upb.crypto.clarc.predicategeneration.rangeproofs.zerotoupowlrangeproof.ZeroToUPowLRangeProofPublicParameters;
import de.upb.crypto.clarc.protocols.arguments.SigmaProtocol;
import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.common.RingElementPlainText;
import de.upb.crypto.craco.sig.ps.*;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.serialization.ListRepresentation;
import de.upb.crypto.math.serialization.ObjectRepresentation;
import de.upb.crypto.math.serialization.Representable;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
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
	long timerStarUser = 0;
	long timerStartProvider = 0;
	private int maxIterations = 100;

	@Before
	public void setup() {
		// measureTime(null);
		IncentiveSystemSetup setup = new IncentiveSystemSetup();
		this.pp = setup.generatePublicParameter(256);
		// measureTime("System setup");

		this.zp = new Zp(pp.group.getG1().size());

		// set up a single user
		// measureTime(null);
		this.user = new IncentiveUser(pp);
		// measureTime("User setup");
		this.userPK = user.keyPair.userPublicKey;
		this.userSK = user.keyPair.userSecretKey;

		// set up a single provider
		//measureTime(null);
		this.provider = new IncentiveProvider(pp);
		// measureTime("Provider setup");
		this.pk = provider.keyPair.providerPublicKey;
		this.sk = provider.keyPair.providerSecretKey;

		// set up signature scheme
		this.signatureScheme = new PSExtendedSignatureScheme(new PSPublicParameters(pp.group.getBilinearMap()));
	}

	@Test
	public void testIssueReceive() {
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
		IncentiveToken userToken = output.token;

		// the balance after issuance should be 0
		assertEquals(userToken.value,zp.getZeroElement());

		// signature in token is valid on pk over usk, dldsig, dsrnd, value (of token)
		MessageBlock msg = new MessageBlock();
		Stream.of(userSK.usk, userToken.dsid, userToken.dsrnd, userToken.value).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));
		assertTrue(signatureScheme.verify(msg, userToken.token, pk));

		// dsidInGroup =? w^dsidInGroup
		assertEquals(userDoubleSpendID, pp.w.pow(userToken.dsid));
	}

	@Test
	public void testCreditEarn() {
		// initialize a token
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
		IncentiveToken userToken = output.token;

		IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken, POINTS_CREDITED);

		// the balance after earn should be POINTS_CREDITED
		assertEquals(updatedToken.value,zp.valueOf(POINTS_CREDITED));

		// dsidInGroup and dsrnd unchanged during credit
		assertEquals(userToken.dsid, updatedToken.dsid);
		assertEquals(userToken.dsrnd, updatedToken.dsrnd);

		// signature still valid?
		MessageBlock updatedMsg = new MessageBlock();
		Stream.of(userSK.usk, updatedToken.dsid, updatedToken.dsrnd, updatedToken.value).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> updatedMsg));
		assertTrue(signatureScheme.verify(updatedMsg, updatedToken.token, pk));
	}

	@Test
	public void testSpendDeduct() {
		// initialize a token
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
		IncentiveToken userToken = output.token;

		// credit POINTS_CREDITED many points
		IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken, POINTS_CREDITED);

		TokenDoubleSpendIdPair spend = spendDeduct(zp, user, provider, pk, userToken.dsid, updatedToken, POINTS_SPENT);

		// balance updated?
		assertEquals(spend.token.value, updatedToken.value.sub(zp.valueOf(POINTS_SPENT)));
	}

	@Test
	public void testSpendDeductNegatively() {
		// initialize a token
		TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
		GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
		IncentiveToken userToken = output.token;

		// credit POINTS_CREDITED many points
		IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken, POINTS_CREDITED);

		// Range proof should throw illegal argument exception when v is not is the range.
		assertThrows(IllegalArgumentException.class, () -> spendDeduct(zp, user, provider, pk, userToken.dsid, updatedToken, POINTS_CREDITED + 19));
	}

	TokenDoubleSpendIdPair spendDeduct(Zp zp, IncentiveUser user, IncentiveProvider provider, PSExtendedVerificationKey pk, Zp.ZpElement userDoubleSpendID, IncentiveToken updatedToken, int pointsSpent) {
		long sizeOfMsgSent = 0;
		// assumption: points k1 spent & double spend id known to both parties
		Zp.ZpElement k1 = zp.valueOf(pointsSpent);

		SpendInstance spendInstance = user.initSpend(pk, k1, userDoubleSpendID, updatedToken);

		// 1st message to provider
		ObjectRepresentation msg1Repr = new ObjectRepresentation();
		msg1Repr.put("k1", k1.getRepresentation());
		msg1Repr.put("userDoubleSpendID", userDoubleSpendID.getRepresentation());
		msg1Repr.put("cUsrStar", spendInstance.cUsrStar.getRepresentation());
		String msg1 = msg1Repr.toString();

		sizeOfMsgSent += msg1.getBytes().length;

		DeductInstance deductInstance = provider.initDeduct(k1, userDoubleSpendID, spendInstance.cUsrStar);

		// 2nd message to user
		ObjectRepresentation msg2Repr = new ObjectRepresentation();
		msg2Repr.put("dsidIsrStar", deductInstance.dsidIsrStar.getRepresentation());
		msg2Repr.put("gamma", deductInstance.gamma.getRepresentation());
		String msg2 = msg2Repr.toString();

		sizeOfMsgSent += msg2.getBytes().length;

		spendInstance.initProtocol(deductInstance.dsidIsrStar, deductInstance.gamma);
		SigmaProtocol rangeProtocol = spendInstance.rangeProtocol;
		Announcement[] schnorrAnnouncements = spendInstance.generateSchnorrAnnoucements();
		ZeroToUPowLRangeProofPublicParameters rangePP = (ZeroToUPowLRangeProofPublicParameters) rangeProtocol.getPublicParameters();
		Announcement[] rangeAnnouncements = rangeProtocol.generateAnnouncements();


		// 3rd message to provider
		ObjectRepresentation msg3Repr = new ObjectRepresentation();
		msg3Repr.put("commitment", spendInstance.commitment.getRepresentation());
		msg3Repr.put("commitmentOnValue", spendInstance.commitmentOnValue.getRepresentation());
		msg3Repr.put("c", spendInstance.c.getRepresentation());
		msg3Repr.put("ctrace", spendInstance.ctrace.getRepresentation());
		msg3Repr.put("schnorrAnnouncements", new ListRepresentation(Arrays.stream(schnorrAnnouncements).map(Representable::getRepresentation).collect(Collectors.toList())));
		msg3Repr.put("rangePP", rangePP.getRepresentation());
		msg3Repr.put("rangeAnnouncements", new ListRepresentation(Arrays.stream(rangeAnnouncements).map(Representable::getRepresentation).collect(Collectors.toList())));
		String msg3 = msg3Repr.toString();

		sizeOfMsgSent += msg3.getBytes().length;

		deductInstance.initProtocol(spendInstance.commitment, spendInstance.commitmentOnValue, spendInstance.c, spendInstance.ctrace, spendInstance.randToken, schnorrAnnouncements, rangePP, rangeAnnouncements);
		deductInstance.chooseChallenge();

		// 4th message to user
		ObjectRepresentation msg4Repr = new ObjectRepresentation();
		msg4Repr.put("schnorrChallenge", deductInstance.schnorrChallenge.getRepresentation());
		msg4Repr.put("rangeChallenge", deductInstance.rangeChallenge.getRepresentation());
		String msg4 = msg4Repr.toString();

		sizeOfMsgSent += msg4.getBytes().length;

		Response[] schnorrResponses = spendInstance.generateSchnorrResponses(deductInstance.schnorrChallenge);
		Response[] rangeResponses = spendInstance.generateRangeResponses(deductInstance.rangeChallenge);

		ObjectRepresentation msg5Repr = new ObjectRepresentation();
		msg5Repr.put("schnorrResponses", new ListRepresentation(Arrays.stream(schnorrResponses).map(Representable::getRepresentation).collect(Collectors.toList())));
		msg5Repr.put("rangeResponses", new ListRepresentation(Arrays.stream(rangeResponses).map(Representable::getRepresentation).collect(Collectors.toList())));
		String msg5 = msg5Repr.toString();

		sizeOfMsgSent += msg5.getBytes().length;

		DeductOutput deduct = deductInstance.deduct(schnorrResponses, rangeResponses);

		ObjectRepresentation msg6Repr = new ObjectRepresentation();
		msg6Repr.put("issuedSignature", deduct.issuedSignature.getRepresentation());
		String msg6 = msg6Repr.toString();

		sizeOfMsgSent += msg6.getBytes().length;

		System.out.println("Network traffic: " + sizeOfMsgSent / 1000);

		TokenDoubleSpendIdPair spend = spendInstance.spend(deduct.issuedSignature);

		return spend;
	}

	IncentiveToken creditEarn(Zp zp, IncentiveUser user, IncentiveProvider provider, PSExtendedVerificationKey pk, IncentiveToken userToken, int pointsCredited) {
		// asssumption: value k credited known to both parties
		Zp.ZpElement k = zp.valueOf(pointsCredited);

		EarnInstance earnInstance = user.initEarn(pk, k, userToken);
		Announcement[] announcements = earnInstance.generateAnnoucements();

		CreditInstance creditInstance = provider.initCredit(k, earnInstance.randToken, announcements);
		Challenge challenge = creditInstance.chooseChallenge();

		Response[] responses = earnInstance.generateResponses(challenge);

		PSSignature blindedSig = creditInstance.credit(responses);

		IncentiveToken earn = earnInstance.earn(blindedSig);
		return earn;
	}

	TokenDoubleSpendIdPair issueReceive(IncentiveUser user, IncentiveUserPublicKey userPK, IncentiveProvider provider, PSExtendedVerificationKey pk) {
		// assumption: exchange common input before-hand
		ReceiveInstance receiveInstance = user.initReceive(pk);

		IssueInstance issueInstance = provider.initIssue(userPK, receiveInstance.cUsr);

		receiveInstance.initProtocol(issueInstance.dsidIsr);
		Announcement[] announcements = receiveInstance.generateAnnoucements();

		issueInstance.initProtocol(receiveInstance.c, announcements);
		Challenge ch = issueInstance.chooseChallenge();

		Response[] responses = receiveInstance.computeResponses(ch);

		PSSignature blindedSignature = issueInstance.issue(responses);

		TokenDoubleSpendIdPair receive = receiveInstance.receive(blindedSignature);
		return receive;
	}

	/* Performance tests */
	@Test
	public void evalIssueReceive() {
		if(maxIterations == 0) return;

		Stopwatch receiveTimer = new Stopwatch("Receive");
		long receiveAcc = 0;
		Stopwatch issueTimer = new Stopwatch("Issue");
		long issueAcc = 0;

		for (int i = 0; i < maxIterations; i++) {

			// assumption: exchange common input before-hand
			receiveTimer.start();
			ReceiveInstance receiveInstance = user.initReceive(pk);
			receiveTimer.stop();

			issueTimer.start();
			IssueInstance issueInstance = provider.initIssue(userPK, receiveInstance.cUsr);
			issueTimer.stop();

			receiveTimer.start();
			receiveInstance.initProtocol(issueInstance.dsidIsr);
			Announcement[] announcements = receiveInstance.generateAnnoucements();
			receiveTimer.stop();

			issueTimer.start();
			issueInstance.initProtocol(receiveInstance.c, announcements);
			Challenge ch = issueInstance.chooseChallenge();
			issueTimer.stop();

			receiveTimer.start();
			Response[] responses = receiveInstance.computeResponses(ch);
			receiveTimer.stop();

			issueTimer.start();
			PSSignature blindedSignature = issueInstance.issue(responses);
			issueTimer.stop();

			receiveTimer.start();
			TokenDoubleSpendIdPair receive = receiveInstance.receive(blindedSignature);
			receiveTimer.stop();

			GroupElement userDoubleSpendID = receive.doubleSpendIDinGroup;
			IncentiveToken userToken = receive.token;

			receiveAcc += receiveTimer.timeElapsed();
			receiveTimer.reset();
			issueAcc += issueTimer.timeElapsed();
			issueTimer.reset();
		}
		System.out.println("AVG timing for protocol Issue/Receive over " + maxIterations + " runs:");
		System.out.println("Receive: " + ((double) receiveAcc) / maxIterations / 1E9);
		System.out.println("Issue: " + ((double) issueAcc) / maxIterations / 1E9);
		System.out.println();
	}

	@Test
	public void evalCreditEarn() {
		if(maxIterations == 0) return;

		Stopwatch earnTimer = new Stopwatch("Earn");
		long earnAcc = 0;
		Stopwatch creditTimer = new Stopwatch("Credit");
		long creditAcc = 0;

		for (int i = 0; i < maxIterations; i++) {
			TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
			IncentiveToken userToken = output.token;
			Zp.ZpElement k = zp.valueOf(POINTS_CREDITED);

			earnTimer.start();
			EarnInstance earnInstance = user.initEarn(pk, k, userToken);
			Announcement[] announcements = earnInstance.generateAnnoucements();
			earnTimer.stop();

			creditTimer.start();
			CreditInstance creditInstance = provider.initCredit(k, earnInstance.randToken, announcements);
			Challenge challenge = creditInstance.chooseChallenge();
			creditTimer.stop();

			earnTimer.start();
			Response[] responses = earnInstance.generateResponses(challenge);
			earnTimer.stop();

			creditTimer.start();
			PSSignature blindedSig = creditInstance.credit(responses);
			creditTimer.stop();

			earnTimer.start();
			IncentiveToken earn = earnInstance.earn(blindedSig);
			earnTimer.stop();

			earnAcc += earnTimer.timeElapsed();
			earnTimer.reset();
			creditAcc += creditTimer.timeElapsed();
			creditTimer.reset();
		}
		System.out.println("AVG timing for protocol Credit/Earn over " + maxIterations + " runs:");
		System.out.println("Earn: " + ((double) earnAcc) / maxIterations / 1E9);
		System.out.println("Credit: " + ((double) creditAcc) / maxIterations / 1E9);
		System.out.println();
	}

	@Test
	public void evalSpendDeduct() {
		if(maxIterations == 0) return;

		Stopwatch spendTimer = new Stopwatch("Spend");
		long spendAcc = 0;
		Stopwatch deductTimer = new Stopwatch("Deduct");
		long deductAcc = 0;

		for (int i = 0; i < maxIterations; i++) {
			TokenDoubleSpendIdPair output = issueReceive(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
			IncentiveToken userToken = output.token;
			IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken, POINTS_CREDITED);

			Zp.ZpElement k1 = zp.valueOf(POINTS_SPENT);

			spendTimer.start();
			SpendInstance spendInstance = user.initSpend(pk, k1, output.token.dsid, updatedToken);
			spendTimer.stop();

			deductTimer.start();
			DeductInstance deductInstance = provider.initDeduct(k1, output.token.dsid, spendInstance.cUsrStar);
			deductTimer.stop();

			spendTimer.start();
			spendInstance.initProtocol(deductInstance.dsidIsrStar, deductInstance.gamma);
			SigmaProtocol rangeProtocol = spendInstance.rangeProtocol;
			Announcement[] schnorrAnnouncements = spendInstance.generateSchnorrAnnoucements();
			ZeroToUPowLRangeProofPublicParameters rangePP = (ZeroToUPowLRangeProofPublicParameters) rangeProtocol.getPublicParameters();
			Announcement[] rangeAnnouncements = rangeProtocol.generateAnnouncements();
			spendTimer.stop();

			deductTimer.start();
			deductInstance.initProtocol(spendInstance.commitment, spendInstance.commitmentOnValue, spendInstance.c, spendInstance.ctrace, spendInstance.randToken, schnorrAnnouncements, rangePP, rangeAnnouncements);
			deductInstance.chooseChallenge();
			deductTimer.stop();

			spendTimer.start();
			Response[] schnorrResponses = spendInstance.generateSchnorrResponses(deductInstance.schnorrChallenge);
			Response[] rangeResponses = spendInstance.generateRangeResponses(deductInstance.rangeChallenge);
			spendTimer.stop();

			deductTimer.start();
			DeductOutput deduct = deductInstance.deduct(schnorrResponses, rangeResponses);
			deductTimer.stop();

			deductTimer.start();
			TokenDoubleSpendIdPair spend = spendInstance.spend(deduct.issuedSignature);
			deductTimer.stop();

			spendAcc += spendTimer.timeElapsed();
			spendTimer.reset();
			deductAcc += deductTimer.timeElapsed();
			deductTimer.reset();
		}
		System.out.println("AVG timing for protocol Spend/Deduct over " + maxIterations + " runs:");
		System.out.println("Spend: " + ((double) spendAcc) / maxIterations /  1E9);
		System.out.println("Deduct: " + ((double) deductAcc) / maxIterations / 1E9);
		System.out.println();
	}
}
