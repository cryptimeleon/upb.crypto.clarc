package de.upb.crypto.clarc.spseqincentive;


import de.upb.crypto.clarc.protocols.parameters.Announcement;
import de.upb.crypto.clarc.protocols.parameters.Challenge;
import de.upb.crypto.clarc.protocols.parameters.Response;
import de.upb.crypto.clarc.utils.Stopwatch;
import de.upb.crypto.craco.common.MessageBlock;
import de.upb.crypto.craco.sig.ps.PSSignature;
import de.upb.crypto.craco.sig.sps.eq.*;
import de.upb.crypto.math.interfaces.structures.GroupElement;
import de.upb.crypto.math.structures.zn.Zp;
import org.junit.Before;
import org.junit.Test;

import static org.junit.jupiter.api.Assertions.*;

public class IncentiveSystemTest {
    IncentiveSystemPublicParameters pp;
    Zp zp;

    IncentiveUser user;
    IncentiveUserPublicKey userPK;
    IncentiveUserSecretKey userSK;

    IncentiveProvider provider;
    IncentiveProviderSecretKey providerSecretKey;
    IncentiveProviderPublicKey providerPublicKey;


    SPSEQSignatureScheme spseqSignatureScheme;

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
        this.providerPublicKey = provider.keyPair.providerPublicKey;
        this.providerSecretKey = provider.keyPair.providerSecretKey;

        // set up signature scheme
        this.spseqSignatureScheme = new SPSEQSignatureScheme(providerPublicKey.spseqPublicParameters);
    }

    @Test
    public void testIssueJoin() {
        TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, providerPublicKey);
        GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
        IncentiveToken userToken = output.token;

        // the balance after issuance should be 0
        assertEquals(userToken.value, zp.getZeroElement());

        // signature in token is valid on pk over usk, dldsig, dsrnd, value (of token)
        // MessageBlock msg = new MessageBlock();
        //Stream.of(userSK.usk, userToken.dsid, userToken.dsrnd, userToken.value).map(RingElementPlainText::new).collect(Collectors.toCollection(() -> msg));
        assertTrue(spseqSignatureScheme.verify(userToken.M, userToken.spseqSignature, providerPublicKey.spseqVerificationKey));

        // dsidInGroup =? w^dsidInGroup
        assertEquals(userDoubleSpendID, pp.w.pow(userToken.esk));
    }

    @Test
    public void testCreditEarn() {
        // initialize a token
        TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, providerPublicKey);
        GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
        IncentiveToken userToken = output.token;

        IncentiveToken updatedToken = creditEarn(zp, user, provider, providerPublicKey, userToken, POINTS_CREDITED);

        // the balance after earn should be POINTS_CREDITED
        assertEquals(updatedToken.value, zp.valueOf(POINTS_CREDITED));

        // dsidInGroup and dsrnd unchanged during credit
        assertEquals(userToken.esk, updatedToken.esk);
        assertEquals(userToken.dsrnd0, updatedToken.dsrnd0);
        assertEquals(userToken.dsrnd1, updatedToken.dsrnd1);

        // signature still valid?
        assertTrue(spseqSignatureScheme.verify(updatedToken.M, updatedToken.spseqSignature, providerPublicKey.spseqVerificationKey));
    }


    @Test
    public void testSpendDeductPhase1() {
        TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, providerPublicKey);
        GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
        IncentiveToken userToken = output.token;

        boolean b = spendDeductPhase1(zp, user, provider, providerPublicKey, userToken, POINTS_SPENT);


        // the balance after earn should be POINTS_CREDITED
        assertTrue(b);

    }

    boolean spendDeductPhase1(Zp zp, IncentiveUser user, IncentiveProvider provider, IncentiveProviderPublicKey pk, IncentiveToken userToken, Integer pointsToSpend) {
        // assumption: exchange common input before-hand
        Zp.ZpElement k = zp.valueOf(pointsToSpend);
        Zp.ZpElement vMinusK = k.sub(userToken.value);

        SpendPhase1Instance spendPhase1Instance = user.initSpendPhase1(pk, vMinusK, userToken);

        DeductPhase1nstance deductPhase1nstance = provider.initDeductPhase1(userPK, vMinusK, pp.w.pow(userToken.esk), spendPhase1Instance.cPre);

        spendPhase1Instance.initProtocol(deductPhase1nstance.eskisr, deductPhase1nstance.gamma, deductPhase1nstance.tid);


        boolean valid = spendPhase1Instance.protocol.isFulfilled();


        Announcement[] announcements = spendPhase1Instance.generateAnnoucements();

        deductPhase1nstance.initProtocol(spendPhase1Instance.cPre, spendPhase1Instance.bCom, announcements);
        Challenge ch = deductPhase1nstance.chooseChallenge();

        Response[] responses = spendPhase1Instance.computeResponses(ch);

        PSSignature psSignature = deductPhase1nstance.endDeductPhase1(responses);

        boolean b = spendPhase1Instance.endPhase1(psSignature);
        return b;
    }

    /*
        @Test
        public void testSpendDeduct() {
            // initialize a token
            TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, pk);
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
            TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, pk);
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

            SpendPhase1Instance spendInstance = user.initSpendPhase1(pk, k1, userDoubleSpendID, updatedToken);

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
    */
    IncentiveToken creditEarn(Zp zp, IncentiveUser user, IncentiveProvider provider, IncentiveProviderPublicKey pk, IncentiveToken userToken, int pointsCredited) {
        // asssumption: value k credited known to both parties
        Zp.ZpElement k = zp.valueOf(pointsCredited);

        EarnInstance earnInstance = user.initEarn(pk, k, userToken);
        //Announcement[] announcements = earnInstance.generateAnnoucements();

        CreditInstance creditInstance = provider.initCredit(k, earnInstance.cPrime, earnInstance.spseqSignature, null);
        //Challenge challenge = creditInstance.chooseChallenge();

        //Response[] responses = earnInstance.generateResponses(challenge);

        SPSEQSignature spseqSignature = creditInstance.credit(null);

        IncentiveToken earn = earnInstance.earn(spseqSignature);
        return earn;
    }


    TokenDoubleSpendIdPair issueJoin(IncentiveUser user, IncentiveUserPublicKey userPK, IncentiveProvider provider, IncentiveProviderPublicKey pk) {
        // assumption: exchange common input before-hand
        JoinInstance joinInstance = user.initJoin(pk);

        IssueInstance issueInstance = provider.initIssue(userPK, joinInstance.cPre);

        joinInstance.initProtocol(issueInstance.eskisr);

        joinInstance.protocol.isFulfilled();

        Announcement[] announcements = joinInstance.generateAnnoucements();

        issueInstance.initProtocol(joinInstance.cPre, joinInstance.bCom, announcements);
        Challenge ch = issueInstance.chooseChallenge();

        Response[] responses = joinInstance.computeResponses(ch);

        SPSEQSignature spseqSignature = issueInstance.issue(responses);

        TokenDoubleSpendIdPair receive = joinInstance.join(spseqSignature);
        return receive;
    }

    //* Performance tests *//*
    @Test
    public void evalIssueJoin() {
        if (maxIterations == 0) return;

        Stopwatch receiveTimer = new Stopwatch("Receive");
        long receiveAcc = 0;
        Stopwatch issueTimer = new Stopwatch("Issue");
        long issueAcc = 0;

        for (int i = 0; i < maxIterations; i++) {

            // assumption: exchange common input before-hand
            receiveTimer.start();
            JoinInstance receiveInstance = user.initJoin(providerPublicKey);
            receiveTimer.stop();

            issueTimer.start();
            IssueInstance issueInstance = provider.initIssue(userPK, receiveInstance.cPre);
            issueTimer.stop();

            receiveTimer.start();
            receiveInstance.initProtocol(issueInstance.eskisr);
            Announcement[] announcements = receiveInstance.generateAnnoucements();
            receiveTimer.stop();

            issueTimer.start();
            issueInstance.initProtocol(receiveInstance.cPre, receiveInstance.bCom, announcements);
            Challenge ch = issueInstance.chooseChallenge();
            issueTimer.stop();

            receiveTimer.start();
            Response[] responses = receiveInstance.computeResponses(ch);
            receiveTimer.stop();

            issueTimer.start();
            SPSEQSignature blindedSignature = issueInstance.issue(responses);
            issueTimer.stop();

            receiveTimer.start();
            TokenDoubleSpendIdPair receive = receiveInstance.join(blindedSignature);
            receiveTimer.stop();

            GroupElement userDoubleSpendID = receive.doubleSpendIDinGroup;
            IncentiveToken userToken = receive.token;

            receiveAcc += receiveTimer.timeElapsed();
            receiveTimer.reset();
            issueAcc += issueTimer.timeElapsed();
            issueTimer.reset();
        }
        System.out.println("AVG timing for protocol Issue/Receive over " + maxIterations + " runs:");
        System.out.println("Join: " + ((double) receiveAcc) / maxIterations / 1E9);
        System.out.println("Issue: " + ((double) issueAcc) / maxIterations / 1E9);
        System.out.println();
    }
/*
	@Test
	public void evalCreditEarn() {
		if(maxIterations == 0) return;

		Stopwatch earnTimer = new Stopwatch("Earn");
		long earnAcc = 0;
		Stopwatch creditTimer = new Stopwatch("Credit");
		long creditAcc = 0;

		for (int i = 0; i < maxIterations; i++) {
			TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, pk);
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
			TokenDoubleSpendIdPair output = issueJoin(user, userPK, provider, pk);
			GroupElement userDoubleSpendID = output.doubleSpendIDinGroup;
			IncentiveToken userToken = output.token;
			IncentiveToken updatedToken = creditEarn(zp, user, provider, pk, userToken, POINTS_CREDITED);

			Zp.ZpElement k1 = zp.valueOf(POINTS_SPENT);

			spendTimer.start();
			SpendPhase1Instance spendInstance = user.initSpendPhase1(pk, k1, output.token.dsid, updatedToken);
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
	}*/
}
