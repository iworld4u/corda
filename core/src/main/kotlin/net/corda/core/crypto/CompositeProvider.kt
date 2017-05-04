package net.corda.core.crypto

import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import java.security.Provider

/**
 * Created by rossnicoll on 04/04/2017.
 */
// TODO: Write info
class CompositeProvider : Provider("X-Corda", 0.1, "") {
    companion object {
        // TODO: Can we get this from the key rather than hard coding it?
        val EDDSA_ALG_IDENTIFIER = AlgorithmIdentifier(ASN1ObjectIdentifier("1.3.6.1.4.1.11591.4.12"))
    }

    init {
        this.putService(CompositeSignature.getService(this))
        // TODO: Find a better way of having these found
        this.putService(Provider.Service(this, "Signature", EDDSA_ALG_IDENTIFIER.algorithm.toString(),
                net.i2p.crypto.eddsa.EdDSAEngine::class.java.name, emptyList(), emptyMap()))
    }
}