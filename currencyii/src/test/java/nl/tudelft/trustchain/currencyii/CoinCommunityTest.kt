@file:Suppress("DEPRECATION")

package nl.tudelft.trustchain.currencyii

import com.goterl.lazycode.lazysodium.LazySodiumJava
import com.goterl.lazycode.lazysodium.SodiumJava
import com.squareup.sqldelight.db.SqlDriver
import com.squareup.sqldelight.sqlite.driver.JdbcSqliteDriver
import io.mockk.*
import junit.framework.Assert.assertEquals
import nl.tudelft.ipv8.IPv8
import nl.tudelft.ipv8.Peer
import nl.tudelft.ipv8.android.IPv8Android
import nl.tudelft.ipv8.attestation.trustchain.*
import nl.tudelft.trustchain.currencyii.coin.WalletManager
import nl.tudelft.trustchain.currencyii.coin.WalletManagerAndroid
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainSQLiteStore
import nl.tudelft.ipv8.attestation.trustchain.store.TrustChainStore
import nl.tudelft.ipv8.keyvault.LibNaClSK
import nl.tudelft.ipv8.keyvault.PrivateKey
import nl.tudelft.ipv8.messaging.EndpointAggregator
import nl.tudelft.ipv8.peerdiscovery.Network
import nl.tudelft.ipv8.sqldelight.Database
import nl.tudelft.ipv8.util.hexToBytes
import nl.tudelft.ipv8.util.toHex
import nl.tudelft.trustchain.currencyii.sharedWallet.*
import org.bitcoinj.core.*
import org.bitcoinj.params.TestNet3Params
import org.junit.Test
import java.util.*
import kotlin.collections.HashMap

private val lazySodium = LazySodiumJava(SodiumJava())

class CoinCommunityTest {

    val ENTRANCE_FEE = 10000L

    val FUNDS_TRANSFER_AMOUNT = 1000L
    val FUNDS_RECEIVER_ADDRESS = "mo4nNbGVfJGozjtD9ViXvcgW1fjq9stdzd"

    val TRUSTCHAIN_PK = "4c69624e61434c504b3a8d56b1bd19d38e9524c04d1a13f6020e56818829ecb3ba9a97bd395380d8336e2a796f574f4391b5ad795ef9740fb5287c7100909c547c85213ef71c9a932857"

    // BTC keys
    val BTC_PK = "mi38Bwzh7GKeTy7w1DNTUF8zNUzoE8LiCs"
    val BTC_PK_2 = "zHeLWRUv1jJn6ciWYMjJrPxv6Gg96US6Fz"

    // TX 1: Creation wallet
    val TX_CREATE_WALLET_ID = "14781fbecf604e5c6cf67d6383dfc9f3f7d8a163e3a82b1154b90675f0a7752c"
    val TX_CREATE_WALLET_SERIALIZED = "0100000001e0fd1e412759b302ef37fc00276b2ba273e17edc7fc441402637fc116aac8883000000006b483045022100ae71317f958f8bda8333fd481e579e7a55e012fc7c90011dd34e79d8fdc5f1e8022020b1d05d7bcda5223973a38f4d6e61fc71cd5ebc4af4264f7e677af5a1934476012102a0f57da74971be3e4299ccb903b994f0bf63a394ec3482f7d009f873512eff4effffffff023336b101000000001976a914ca7811b425f1b4398a638dcb7245a0d7271f942688ac10270000000000002551210357e6900d88e1fecddaaef1dbc392ef9647f0e49c7905b3a273f54a5dae0003a651ae00000000"

    // TX 2: Add user to wallet
    val TX_ADD_USER_ID = "14781fbecf604e5c6cf67d6383dfc9f3f7d8a163e3a82b1154b90675f0a7752c"
    val TX_ADD_USER_SERIALIZED = "0100000001c85d15fd6a09dd0abb81c02073e8122cfee753272bdb45319ece699217f9466e000000009100473044022033c5b2b3a6a170aa5f236ddff5b43d50de95ca04b7d6a0656e2866bbfc31a882022018c6edf69a39ae7ce4dbb9c7f837214e34cf78f0c886832137a5e383d13fe5bf0147304402201ecbd8f36e85fd27d301e8142ae7dbf070d4b7ce6c8cb2067f0db62d3e5e793802206c70650fb76f0f30885cbd9e7a18ad92f31570b57db1a2800a717530841e0b1f01ffffffff02e8030000000000001976a91452cde8b3a35836ecb011d82882dd3d02e8e895e188acad3e0000000000006752210357e6900d88e1fecddaaef1dbc392ef9647f0e49c7905b3a273f54a5dae0003a64104b8439dec935d9abda33194d27a1d0a86f4e52b702475ed13d4ae83501e50d5d71402189b6229163e1afbae663eb0df305e2d9b5b61bdcd0125a2360d2cd3200e52ae00000000"

    // TX 3: Transfer funds
    val TX_TRANSFER_FUNDS_ID = "768876624493431b079ec883326e4c23bddba20a0c870bfe23989ca0991c88fc"
    val TX_TRANSFER_FUNDS_SERIALIZED = "0100000001c85d15fd6a09dd0abb81c02073e8122cfee753272bdb45319ece699217f9466e000000009100473044022033c5b2b3a6a170aa5f236ddff5b43d50de95ca04b7d6a0656e2866bbfc31a882022018c6edf69a39ae7ce4dbb9c7f837214e34cf78f0c886832137a5e383d13fe5bf0147304402201ecbd8f36e85fd27d301e8142ae7dbf070d4b7ce6c8cb2067f0db62d3e5e793802206c70650fb76f0f30885cbd9e7a18ad92f31570b57db1a2800a717530841e0b1f01ffffffff02e8030000000000001976a91452cde8b3a35836ecb011d82882dd3d02e8e895e188acad3e0000000000006752210357e6900d88e1fecddaaef1dbc392ef9647f0e49c7905b3a273f54a5dae0003a64104b8439dec935d9abda33194d27a1d0a86f4e52b702475ed13d4ae83501e50d5d71402189b6229163e1afbae663eb0df305e2d9b5b61bdcd0125a2360d2cd3200e52ae00000000"

    val SW_BLOCK_HASH = ByteArray(10)

    // Trustchain vars
    val GENESIS_HASH = ByteArray(32) { '0'.toByte() }
    val EMPTY_SIG = ByteArray(64) { '0'.toByte() }
    val EMPTY_PK = ByteArray(74) { '0'.toByte() }
    val ANY_COUNTERPARTY_PK = EMPTY_PK

    // ======================================
    //  PROTOCOL HAPPY PATH TESTS
    // ======================================

    // 1.1 + 1.2
    @Test
    fun testTrustGenesisBlock() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager

        val transactionPackage = mockk<WalletManager.TransactionPackage>()
        every { transactionPackage.transactionId } returns TX_CREATE_WALLET_ID
        every { walletManager.safeCreationAndSendGenesisWallet(Coin.valueOf(ENTRANCE_FEE)) } returns transactionPackage
        every { walletManager.attemptToGetTransactionAndSerialize(TX_CREATE_WALLET_ID) } returns TX_CREATE_WALLET_SERIALIZED
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any<ByteArray>(), any<String>()) } returns Unit

        // Actual test
        val txId = coinCommunity.createGenesisSharedWallet(ENTRANCE_FEE)
        val serializedTx = coinCommunity.fetchBitcoinTransaction(txId)
        coinCommunity.broadcastCreatedSharedWallet(serializedTx!!, ENTRANCE_FEE, 1)

        // Verify that the trustchain method is called
        verify { trustchain.createProposalBlock(any<String>(), TRUSTCHAIN_PK.hexToBytes(),
            CoinCommunity.SHARED_WALLET_BLOCK
        ) }
    }

    // 2.1: Join wallet of BTC_PK as BTC_PK_2
    @Test
    fun testTrustchainCreateBitcoinSharedWallet() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK_2
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns swJoinBlock

        // Setup mock trustchain block
        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_CREATE_WALLET_SERIALIZED,
            100,
            arrayListOf(TRUSTCHAIN_PK),
            arrayListOf(BTC_PK)
        )
        every { swJoinBlock.transaction } returns hashMapOf("message" to blockData.getJsonString())

        val newTransactionProposalMock = WalletManager.TransactionPackage(TX_ADD_USER_ID, TX_ADD_USER_SERIALIZED)
        every { walletManager.safeCreationJoinWalletTransaction(any(), any(), any(), any()) } returns newTransactionProposalMock

        // Actual test
        val newTransactionProposal =
            coinCommunity.createBitcoinSharedWallet(SW_BLOCK_HASH)

        assertEquals("Old wallet TX in block is not correct", TX_ADD_USER_ID, newTransactionProposal.transactionId)
        assertEquals("New wallet TX in block is not correct", TX_ADD_USER_SERIALIZED, newTransactionProposal.serializedTransaction)

        val verifyTransaction = Transaction(walletManager.params, TX_CREATE_WALLET_SERIALIZED.hexToBytes())
        verify(exactly = 1) {
            walletManager.safeCreationJoinWalletTransaction(
                arrayListOf(BTC_PK, BTC_PK_2),
                Coin.valueOf(ENTRANCE_FEE),
                verifyTransaction,
                2)
        }
    }

    // 2.3
    @Test
    fun testTrustchainAddSharedWalletJoinBlock() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns swJoinBlock

        // Setup mock trustchain block
        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_CREATE_WALLET_SERIALIZED,
            100,
            arrayListOf(TRUSTCHAIN_PK),
            arrayListOf(BTC_PK)
        )
        every { swJoinBlock.transaction } returns hashMapOf("message" to blockData.getJsonString())

        // Actual test
        coinCommunity.addSharedWalletJoinBlock(SW_BLOCK_HASH)

        verify {
            trustchain.createProposalBlock(
                any<String>(),
                any(),
                CoinCommunity.SHARED_WALLET_BLOCK
            )
        }
    }

    // 2.2 + 2.4
    @Test
    fun testTrustchainSafeSendingJoinWalletTransaction() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns swJoinBlock

        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_CREATE_WALLET_SERIALIZED,
            1,
            arrayListOf(TRUSTCHAIN_PK),
            arrayListOf(BTC_PK)
        )

        val trustChainTransaction = hashMapOf("message" to blockData.getJsonString())
        every { swJoinBlock.transaction } returns trustChainTransaction

        val newTransactionPackage = WalletManager.TransactionPackage("id", "serialized")
        every { walletManager.safeSendingJoinWalletTransaction(any(), any(), any()) } returns newTransactionPackage

        // Actual test
        val swSignatureAskTransactionData =
            coinCommunity.proposeJoinWalletOnTrustChain(SW_BLOCK_HASH, TX_ADD_USER_SERIALIZED)

        // just using an empty list of signatures since walletManager is mocked anyway
        val sigList = listOf<String>()
        val sigListECDSA = sigList.map {
            ECKey.ECDSASignature.decodeFromDER(it.hexToBytes())
        }
        coinCommunity.safeSendingJoinWalletTransaction(swSignatureAskTransactionData, sigList)

        val txOld = Transaction(walletManager.params, TX_CREATE_WALLET_SERIALIZED.hexToBytes())
        val txNew = Transaction(walletManager.params, TX_ADD_USER_SERIALIZED.hexToBytes())

        verify {
            walletManager.safeSendingJoinWalletTransaction(
                sigListECDSA,
                txNew,
                txOld
            )
        }
    }

    // 3.1
    @Test
    fun testTrustchainAskForTransferFundsSignatures() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns swJoinBlock

        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_CREATE_WALLET_SERIALIZED,
            100,
            arrayListOf("trustchain_pk1"),
            arrayListOf("btc_pk1")
        )

        val trustChainTransaction = hashMapOf("message" to blockData.getJsonString())
        every { swJoinBlock.transaction } returns trustChainTransaction

        val newTransactionProposal = WalletManager.TransactionPackage("id", "serialized")
        every { walletManager.safeCreationJoinWalletTransaction(any(), any(), any(), any()) } returns newTransactionProposal

        // Actual test
        val askSignatureBlockData =
            coinCommunity.askForTransferFundsSignatures(SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)

        assertEquals("Signatures required invalid", 1, askSignatureBlockData.getData().SW_SIGNATURES_REQUIRED)

        verify {
            trustchain.createProposalBlock(
                any<String>(),
                any(),
                CoinCommunity.TRANSFER_FUNDS_ASK_BLOCK
            )
        }
    }

    // 3.2
    @Test
    fun testTrustchainTransferFunds() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        val swJoinBlockTransaction = mapOf(Pair(CoinCommunity.SW_TRANSACTION_SERIALIZED, TX_ADD_USER_SERIALIZED))
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { coinCommunity["fetchLatestSharedWalletTransactionBlock"](SW_BLOCK_HASH) } returns swJoinBlock
        every { swJoinBlock.transaction } returns swJoinBlockTransaction

        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_ADD_USER_SERIALIZED,
            100,
            arrayListOf(TRUSTCHAIN_PK, TRUSTCHAIN_PK),
            arrayListOf(BTC_PK, BTC_PK_2)
        )

        val trustChainTransaction = hashMapOf("message" to blockData.getJsonString())
        every { swJoinBlock.transaction } returns trustChainTransaction

        val newTransactionProposal = WalletManager.TransactionPackage(TX_TRANSFER_FUNDS_ID, TX_TRANSFER_FUNDS_SERIALIZED)
        every {
            walletManager.safeSendingTransactionFromMultiSig(
                any(),
                any(),
                any(),
                any()
            )
        } returns newTransactionProposal

        // Actual test
        // just using an empty list of signatures since walletManager is mocked anyway
        val serializedSignatures = listOf<String>()
        val sigListECDSA = serializedSignatures.map {
            ECKey.ECDSASignature.decodeFromDER(it.hexToBytes())
        }
        val txPackage =
            coinCommunity.transferFunds(serializedSignatures, SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)

        val verifyTransaction = Transaction(walletManager.params, TX_TRANSFER_FUNDS_SERIALIZED.hexToBytes())
        val verifyAddress = Address.fromString(walletManager.params, FUNDS_RECEIVER_ADDRESS)
        val verifyCoinAmount = Coin.valueOf(FUNDS_TRANSFER_AMOUNT)
        verify {
            walletManager.safeSendingTransactionFromMultiSig(
            verifyTransaction,
            sigListECDSA,
            verifyAddress,
            verifyCoinAmount)
        }

        assertEquals("Tx ID is not correct in tx package", TX_TRANSFER_FUNDS_ID, txPackage.transactionId)
        assertEquals("Serialized Tx is not correct in tx package", TX_TRANSFER_FUNDS_SERIALIZED, txPackage.serializedTransaction)
    }


    // ======================================
    //  PROTOCOL EDGE CASE TESTS
    // ======================================


    // Invalid Trustchain Community
    @Test(expected = IllegalStateException::class)
    fun testNullTrustChainCommunity() {
        // Setup mocks
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns null

        // Call some random method that gets the trustchain community
        coinCommunity.createBitcoinSharedWallet(ByteArray(0))
    }

    // 2.1
    @Test(expected = IllegalStateException::class)
    fun testTrustchainCreateBitcoinSharedWalletInvalidBlock() {
        // Setup mocks
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns null

        // Actual test
        coinCommunity.createBitcoinSharedWallet(SW_BLOCK_HASH)
    }

    // 2.2
    @Test(expected = IllegalStateException::class)
    fun testTrustchainSafeSendingJoinWalletTransactionInvalidBlock() {
        // Setup mocks
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns null

        // Actual test
        coinCommunity.proposeJoinWalletOnTrustChain(SW_BLOCK_HASH, "")
    }

    // 2.3
    @Test(expected = IllegalStateException::class)
    fun testTrustchainAddSharedWalletJoinBlockInvalidBlock() {
        // Setup mocks
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns null

        // Actual test
        coinCommunity.addSharedWalletJoinBlock(SW_BLOCK_HASH)
    }

    // 2.3
    @Test(expected = IllegalStateException::class)
    fun testTrustchainAskForTransferFundsSignaturesInvalidBlock() {
        // Setup mocks
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns null

        // Actual test
        coinCommunity.askForTransferFundsSignatures(SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)
    }

    // 3.2
    @Test(expected = IllegalStateException::class)
    fun testTrustchainTransferFundsInvalidBlockHash() {
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { trustChainStore.getBlockWithHash(SW_BLOCK_HASH) } returns null // <- block is not found

        coinCommunity.transferFunds(listOf(), SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)
    }

    // 3.2
    @Test(expected = IllegalStateException::class)
    fun testTrustchainTransferFundsInvalidTxOnTrustchainBlock() {
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val swJoinBlock = mockk<TrustChainBlock>()
        val swJoinBlockTransaction = HashMap<String, String>() // <- invalid transaction, serialized tx not in the map
        every { coinCommunity["fetchLatestSharedWalletTransactionBlock"](SW_BLOCK_HASH) } returns swJoinBlock
        every { swJoinBlock.transaction } returns swJoinBlockTransaction

        coinCommunity.transferFunds(listOf(), SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)
    }

    // 3.2
    @Test(expected = IllegalStateException::class)
    fun testTrustchainTransferFundsInvalidSignatures() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK
        every { walletManager.params } returns TestNet3Params.get()

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustchain = mockk<TrustChainHelper>()
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()
        every { coinCommunity getProperty "trustchain" } returns trustchain
        every { trustchain.createProposalBlock(any<String>(), any(), any()) } returns Unit

        val trustChainCommunity = mockk<TrustChainCommunity>()
        val trustChainStore = mockk<TrustChainStore>()
        val iPv8 = mockk<IPv8>()
        val swJoinBlock = mockk<TrustChainBlock>()
        val swJoinBlockTransaction = mapOf(Pair(CoinCommunity.SW_TRANSACTION_SERIALIZED, TX_ADD_USER_SERIALIZED))
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { trustChainCommunity.database } returns trustChainStore
        every { coinCommunity["fetchLatestSharedWalletTransactionBlock"](SW_BLOCK_HASH) } returns swJoinBlock
        every { swJoinBlock.transaction } returns swJoinBlockTransaction

        val blockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_ADD_USER_SERIALIZED,
            100,
            arrayListOf(TRUSTCHAIN_PK, TRUSTCHAIN_PK),
            arrayListOf(BTC_PK, BTC_PK_2)
        )

        val trustChainTransaction = hashMapOf("message" to blockData.getJsonString())
        every { swJoinBlock.transaction } returns trustChainTransaction

        every {
            walletManager.safeSendingTransactionFromMultiSig( any(), any(), any(), any() )
        } returns null

        // Actual test
        // just using an empty list of signatures since walletManager is mocked anyway
        val serializedSignatures = listOf<String>()
        coinCommunity.transferFunds(serializedSignatures, SW_BLOCK_HASH, FUNDS_RECEIVER_ADDRESS, FUNDS_TRANSFER_AMOUNT)
    }


    // ======================================
    //  UTIL METHOD TESTS
    // ======================================

    fun createSharedWalletBlock(blockData: SWBlockTransactionData, trustchainKey: ByteArray, sequenceNumber: UInt): TrustChainBlock {
        val trustchainTransaction = TransactionEncoding.encode(mapOf("message" to blockData.getJsonString()))
        return TrustChainBlock(
            blockData.blockType,
            trustchainTransaction,
            trustchainKey,
            sequenceNumber,
            ANY_COUNTERPARTY_PK,
            0u,
            GENESIS_HASH,
            EMPTY_SIG,
            Date()
        )
    }


    @Test
    fun testSharedWalletDiscovery() {
        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustChainCommunity = mockk<TrustChainCommunity>()
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity
        every { coinCommunity.myPeer.publicKey.keyToBin() } returns TRUSTCHAIN_PK.hexToBytes()

        val driver: SqlDriver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY)
        Database.Schema.create(driver)
        val database = Database(driver)
        val trustChainStore = TrustChainSQLiteStore(database)

        val trustchainKey = TRUSTCHAIN_PK.hexToBytes()

        val createSWBlockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            TX_CREATE_WALLET_SERIALIZED,
            1,
            arrayListOf(trustchainKey.toHex()),
            arrayListOf(BTC_PK)
        )
        val joinBlockData = SWJoinBlockTransactionData(
            ENTRANCE_FEE,
            createSWBlockData.getData().SW_TRANSACTION_SERIALIZED,
            2,
            arrayListOf(trustchainKey.toHex()),
            arrayListOf(BTC_PK, BTC_PK_2)
        )
        val sigAskBlockData = SWSignatureAskTransactionData(
            joinBlockData.getData().SW_UNIQUE_ID,
            TX_ADD_USER_SERIALIZED,
            TX_CREATE_WALLET_SERIALIZED,
            2
        )
        val sigResponseBlockData1 = SWResponseSignatureTransactionData(
            joinBlockData.getData().SW_UNIQUE_ID,
            sigAskBlockData.getData().SW_UNIQUE_ID,
            "MOCK SIGNATURE 1"
        )
        val sigResponseBlockData2 = SWResponseSignatureTransactionData(
            joinBlockData.getData().SW_UNIQUE_ID,
            sigAskBlockData.getData().SW_UNIQUE_ID,
            "MOCK SIGNATURE 2"
        )
        val transferFundsAskBlockData = SWTransferFundsAskTransactionData(
            joinBlockData.getData().SW_UNIQUE_ID,
            TX_ADD_USER_SERIALIZED,
            2,
            FUNDS_TRANSFER_AMOUNT,
            arrayListOf(BTC_PK, BTC_PK_2),
            FUNDS_RECEIVER_ADDRESS
        )

        val createSWBlock = createSharedWalletBlock(createSWBlockData, trustchainKey, 1u)
        val joinBlock = createSharedWalletBlock(joinBlockData, trustchainKey, 2u)
        val sigAskBlock = createSharedWalletBlock(sigAskBlockData, trustchainKey, 3u)
        val sigResponseBlock1 = createSharedWalletBlock(sigResponseBlockData1, trustchainKey, 4u)
        val sigResponseBlock2 = createSharedWalletBlock(sigResponseBlockData2, trustchainKey, 5u)
        val transferFundsAskBlock = createSharedWalletBlock(transferFundsAskBlockData, trustchainKey, 6u)

        trustChainStore.addBlock(createSWBlock)
        trustChainStore.addBlock(joinBlock)
        trustChainStore.addBlock(sigAskBlock)
        trustChainStore.addBlock(sigResponseBlock1)
        trustChainStore.addBlock(sigResponseBlock2)
        trustChainStore.addBlock(transferFundsAskBlock)

        println(createSWBlock.transaction.get("message"))
        println(joinBlock.transaction.get("message"))
        println(sigAskBlock.transaction.get("message"))
        println(sigResponseBlock1.transaction.get("message"))
        println(sigResponseBlock2.transaction.get("message"))
        println(transferFundsAskBlock.transaction.get("message"))

        every { trustChainCommunity.database } returns trustChainStore

        val sharedWallets = coinCommunity.discoverSharedWallets()
        println(sharedWallets)

        val latestSharedWallets = coinCommunity.fetchLatestJoinedSharedWalletBlocks()
        assertEquals(2, latestSharedWallets.size)
        assertEquals(createSWBlock, latestSharedWallets[0])
        assertEquals(joinBlock, latestSharedWallets[1])

        val proposalSignatures = coinCommunity.fetchProposalSignatures(
            joinBlockData.getData().SW_UNIQUE_ID,
            sigAskBlockData.getData().SW_UNIQUE_ID
        )

        println(proposalSignatures)
    }


    // ======================================
    //  FULL TEST
    // ======================================

    // 1.1 + 1.2
    @Test
    fun testRealTrustGenesisBlock() {
        // Setup mocks
        val walletManager = mockk<WalletManager>()
        mockkObject(WalletManagerAndroid)
        every { WalletManagerAndroid.getInstance() } returns walletManager

        val txPackageCreateWallet = mockk<WalletManager.TransactionPackage>()
        every { txPackageCreateWallet.transactionId } returns TX_CREATE_WALLET_ID
        every { walletManager.safeCreationAndSendGenesisWallet(Coin.valueOf(ENTRANCE_FEE)) } returns txPackageCreateWallet
        every { walletManager.attemptToGetTransactionAndSerialize(TX_CREATE_WALLET_ID) } returns TX_CREATE_WALLET_SERIALIZED
        every { walletManager.networkPublicECKeyHex() } returns BTC_PK

        val driver: SqlDriver = JdbcSqliteDriver(JdbcSqliteDriver.IN_MEMORY)
        Database.Schema.create(driver)
        val database = Database(driver)
        val trustChainStore = TrustChainSQLiteStore(database)

        val coinCommunity = spyk(CoinCommunity(), recordPrivateCalls = true)
        val trustChainCommunity = TrustChainCommunity(TrustChainSettings(), trustChainStore)
        val iPv8 = mockk<IPv8>()
        mockkObject(IPv8Android)
        every { IPv8Android.getInstance() } returns iPv8
        every { iPv8.getOverlay<TrustChainCommunity>() } returns trustChainCommunity

        val peerUser1 = getNewPeer()
        val peerUser2 = getNewPeer()
        trustChainCommunity.myPeer = peerUser1
        trustChainCommunity.network = Network()
        trustChainCommunity.endpoint = getEndpoint()
        every { coinCommunity.myPeer } returns peerUser1

        // Actual test
        // 1.1 + 1.2
        val txId = coinCommunity.createGenesisSharedWallet(ENTRANCE_FEE)
        val serializedTx = coinCommunity.fetchBitcoinTransaction(txId)
        coinCommunity.broadcastCreatedSharedWallet(serializedTx!!, ENTRANCE_FEE, 100)

        assertEquals(1, trustChainStore.getAllBlocks().size)
        assertEquals(1, coinCommunity.discoverSharedWallets().size)

        println("After 1.1 + 1.2")
        logAllBlocks(trustChainStore)


        // TODO: ADD ASSERTIONS



        // mocks added for 2.1:
        every { walletManager.params } returns TestNet3Params.get()
        val txPackageJoinUser = WalletManager.TransactionPackage(TX_ADD_USER_ID, TX_ADD_USER_SERIALIZED)
        every { walletManager.safeCreationJoinWalletTransaction(any(), any(), any(), any()) } returns txPackageJoinUser

        // 2.1
        trustChainCommunity.myPeer = peerUser2
        val user2ECKey = ECKey()
        every { coinCommunity.myPeer } returns peerUser2
        every { walletManager.protocolECKey() } returns user2ECKey
        val swBlockHashCreateWallet = coinCommunity.discoverSharedWallets()[0].calculateHash()
        val txPackageJoinWallet = coinCommunity.createBitcoinSharedWallet(swBlockHashCreateWallet)
        println(txPackageJoinWallet.serializedTransaction)

        println("After 2.1")
        logAllBlocks(trustChainStore)

        // 2.2
        val sigAskTransactionData = coinCommunity.proposeJoinWalletOnTrustChain(swBlockHashCreateWallet, txPackageJoinWallet.serializedTransaction)
        assertEquals(2, trustChainStore.getAllBlocks().size)
        assertEquals(1, coinCommunity.discoverSharedWallets().size)

        println("After 2.2")
        logAllBlocks(trustChainStore)

        // Join the shared wallet
        val txHash = Sha256Hash.of(sigAskTransactionData.getData().SW_TRANSACTION_SERIALIZED.toByteArray())
        val user1ECKey = ECKey()
        val user1Signature = user1ECKey.sign(txHash)
        every { walletManager.protocolECKey() } returns user1ECKey
        every { walletManager.safeSigningJoinWalletTransaction(any(), any(), any()) } returns user1Signature
        val trustChainBlockToSign = trustChainStore.getAllBlocks().last()
        CoinCommunity.joinAskBlockReceived(trustChainBlockToSign, peerUser1.publicKey.keyToBin())

        println("After Signature")
        logAllBlocks(trustChainStore)

        // 2.3
        val swBlocks = coinCommunity.discoverSharedWallets()
        val latestSWBlock = swBlocks.last()
        coinCommunity.addSharedWalletJoinBlock(latestSWBlock.calculateHash())

        println("After 2.3")
        logAllBlocks(trustChainStore)

        // 2.4
        val latestSigAskBlock = SWSignatureAskTransactionData(trustChainCommunity.database.getBlocksWithType(CoinCommunity.SIGNATURE_ASK_BLOCK).last().transaction)
        val sigResponseBlocks = trustChainCommunity.database.getBlocksWithType(CoinCommunity.SIGNATURE_AGREEMENT_BLOCK)
        val signatures = sigResponseBlocks.map { signatureBlock ->
            SWResponseSignatureTransactionData(signatureBlock.transaction).getData().SW_SIGNATURE_SERIALIZED
        }

        every { walletManager.safeSendingJoinWalletTransaction(any(), any(), any()) } returns txPackageJoinUser
        coinCommunity.safeSendingJoinWalletTransaction(latestSigAskBlock, signatures)

        println("After 2.4")
        logAllBlocks(trustChainStore)


        // TODO: ADD ASSERTIONS



        // 3.1
        val latestSWBlockForTransfer = coinCommunity.fetchLatestJoinedSharedWalletBlocks().last()
        coinCommunity.askForTransferFundsSignatures(
            latestSWBlockForTransfer.calculateHash(),
            FUNDS_RECEIVER_ADDRESS,
            FUNDS_TRANSFER_AMOUNT
        )
        println("After 3.1")
        logAllBlocks(trustChainStore)

        // Create signatures
        val blockToSignUser1 = trustChainStore.getBlocksWithType(CoinCommunity.TRANSFER_FUNDS_ASK_BLOCK)
            .filter { block -> block.linkPublicKey.contentEquals(peerUser1.publicKey.keyToBin())}
        val blockToSignUser2 = trustChainStore.getBlocksWithType(CoinCommunity.TRANSFER_FUNDS_ASK_BLOCK)
            .filter { block -> block.linkPublicKey.contentEquals(peerUser2.publicKey.keyToBin())}
        println("Signature blocks")
        blockToSignUser1.forEach { block -> println("${block.type}: ${block.publicKey.toHex()} -> ${block.linkPublicKey.toHex()}: ${block.transaction}")}
        blockToSignUser2.forEach { block -> println("${block.type}: ${block.publicKey.toHex()} -> ${block.linkPublicKey.toHex()}: ${block.transaction}")}

        assertEquals(1, blockToSignUser1.size)
        assertEquals(1, blockToSignUser2.size)


        // Signature mocks
        val blockTxHash: Sha256Hash = Sha256Hash.of("TX".toByteArray())
        val mockTransferSigUser1 = user1ECKey.sign(blockTxHash)
        val mockTransferSigUser2 = user2ECKey.sign(blockTxHash)
        every { walletManager.safeSigningTransactionFromMultiSig(any(), user1ECKey, any(), any()) } returns mockTransferSigUser1
        every { walletManager.safeSigningTransactionFromMultiSig(any(), user2ECKey, any(), any()) } returns mockTransferSigUser2

        every { walletManager.protocolECKey() } returns user1ECKey
        CoinCommunity.transferFundsBlockReceived(blockToSignUser1[0], peerUser1.publicKey.keyToBin())

        every { walletManager.protocolECKey() } returns user2ECKey
        CoinCommunity.transferFundsBlockReceived(blockToSignUser2[0], peerUser2.publicKey.keyToBin())

        println("After signatures")
        logAllBlocks(trustChainStore)

        // 3.2
        val lastProposal = SWTransferFundsAskTransactionData(trustChainStore.getBlocksWithType(CoinCommunity.TRANSFER_FUNDS_ASK_BLOCK).last().transaction).getData()
        val transferFundsSignatures = trustChainStore.getBlocksWithType(CoinCommunity.SIGNATURE_AGREEMENT_BLOCK)
            .filter { block -> SWResponseSignatureTransactionData(block.transaction).matchesProposal(lastProposal.SW_UNIQUE_ID, lastProposal.SW_UNIQUE_PROPOSAL_ID) }
            .map { block -> SWResponseSignatureTransactionData(block.transaction).getData().SW_SIGNATURE_SERIALIZED }

        val txPackageTransferFunds = WalletManager.TransactionPackage(TX_TRANSFER_FUNDS_ID, TX_TRANSFER_FUNDS_SERIALIZED)
        every { walletManager.safeSendingTransactionFromMultiSig(any(), any(), any(), any()) } returns txPackageTransferFunds
        coinCommunity.transferFunds(
            transferFundsSignatures,
            coinCommunity.discoverSharedWallets().last().calculateHash(),
            FUNDS_RECEIVER_ADDRESS,
            FUNDS_TRANSFER_AMOUNT
        )

        println("After 3.2")
        logAllBlocks(trustChainStore)


        // 3.3
        val lastAskProposal = SWTransferFundsAskTransactionData(trustChainStore.getBlocksWithType(CoinCommunity.TRANSFER_FUNDS_ASK_BLOCK).last().transaction)
        coinCommunity.postTransactionSucceededOnTrustChain(lastAskProposal, txPackageTransferFunds.serializedTransaction)

        println("After 3.3")
        logAllBlocks(trustChainStore)


        // TODO: ADD ASSERTIONS
    }

    fun logAllBlocks(trustChainStore: TrustChainStore) {
        trustChainStore.getAllBlocks().forEach { block -> println("${block.type}: ${block.publicKey.toHex()} -> ${block.linkPublicKey.toHex()}: ${block.transaction}")}
        println()
    }

    protected fun generatePrivateKey(): PrivateKey {
        return LibNaClSK.generate(lazySodium)
    }

    protected fun getNewPeer(): Peer {
        return Peer(generatePrivateKey())
    }

    protected fun getEndpoint(): EndpointAggregator {
        return spyk(EndpointAggregator(mockk(relaxed = true), null))
    }
}
