package net.corda.node.services.network

import net.corda.core.crypto.*
import net.corda.core.serialization.serialize
import net.corda.core.utilities.ALICE
import net.corda.core.utilities.BOB
import net.corda.node.services.identity.InMemoryIdentityService
import net.corda.testing.ALICE_PUBKEY
import net.corda.testing.BOB_PUBKEY
import org.bouncycastle.asn1.x500.X500Name
import org.junit.Test
import java.security.InvalidAlgorithmParameterException
import java.security.Security
import java.security.cert.*
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

/**
 * Tests for the in memory identity service.
 */
class InMemoryIdentityServiceTests {
    @Test
    fun `get all identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.getAllIdentities().firstOrNull())
        service.registerIdentity(ALICE)
        var expected = setOf(ALICE)
        var actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)

        // Add a second party and check we get both back
        service.registerIdentity(BOB)
        expected = setOf(ALICE, BOB)
        actual = service.getAllIdentities().toHashSet()
        assertEquals(expected, actual)
    }

    @Test
    fun `get identity by key`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromKey(ALICE_PUBKEY))
        service.registerIdentity(ALICE)
        assertEquals(ALICE, service.partyFromKey(ALICE_PUBKEY))
        assertNull(service.partyFromKey(BOB_PUBKEY))
    }

    @Test
    fun `get identity by name with no registered identities`() {
        val service = InMemoryIdentityService()
        assertNull(service.partyFromX500Name(ALICE.name))
    }

    @Test
    fun `get identity by name`() {
        val service = InMemoryIdentityService()
        val identities = listOf("Node A", "Node B", "Node C")
                .map { Party(X500Name("CN=$it,O=R3,OU=corda,L=London,C=UK"), generateKeyPair().public) }
        assertNull(service.partyFromX500Name(identities.first().name))
        identities.forEach { service.registerIdentity(it) }
        identities.forEach { assertEquals(it, service.partyFromX500Name(it.name)) }
    }

    /**
     * Generate a certificate path from a root CA, down to a transaction key, store and verify the association.
     */
    @Test
    fun `assert anonymous key owned by identity`() {
        val (rootCertAndKey, txCertAndKey, txCertPath) = generateAnonymousCertificatePath(ALICE.name)
        val service = InMemoryIdentityService()
        val rootCertificate = rootCertAndKey.certificate
        val rootKey = rootCertAndKey.keyPair
        // TODO: Generate certificate with an EdDSA key rather than ECDSA
        val identity = Party(ALICE.name, rootKey.public)
        val txIdentity = AnonymousParty(txCertAndKey.keyPair.public)

        service.registerPath(rootCertificate, txIdentity, txCertPath)
        service.assertOwnership(identity, txIdentity)
    }

    // TODO: Ensure an invalid certificate path is rejected

    private fun generateAnonymousCertificatePath(name: X500Name): Triple<X509Utilities.CACertAndKey, X509Utilities.CACertAndKey, CertPath> {
        val rootCertAndKey = X509Utilities.createSelfSignedCACert(name)
        val txCertAndKey = X509Utilities.createIntermediateCert(name, rootCertAndKey)
        val intermediateCertificates = setOf(txCertAndKey.certificate)
        val certStore = CertStore.getInstance("Collection", CollectionCertStoreParameters(intermediateCertificates))
        val certPathFactory = CertPathBuilder.getInstance("PKIX")
        val trustAnchor = TrustAnchor(rootCertAndKey.certificate, null)
        val pkixBuilderParameters = try {
            PKIXBuilderParameters(setOf(trustAnchor), X509CertSelector().apply {
                certificate = txCertAndKey.certificate
            })
        } catch (ex: InvalidAlgorithmParameterException) {
            throw RuntimeException(ex)
        }.apply {
            addCertStore(certStore)
            isRevocationEnabled = false
        }

        return Triple(rootCertAndKey, txCertAndKey, certPathFactory.build(pkixBuilderParameters).certPath)
    }
}
