package de.twenty20.cmp.response

import org.bouncycastle.asn1.cmp.PKIStatusInfo
import java.math.BigInteger
import java.security.cert.X509Certificate

/**
 *
 * @author Joscha Vack - twenty20
 */

/**
 * Response to a certification revocation request
 */
sealed class RevocationResponse : BaseResponse() {
    class Success(val revokedCertificates: List<BigInteger>) : RevocationResponse()

    class Failure(
        val revokedCertificates: List<BigInteger>,
        val failedRevocations: List<FailureInfo>
    ) : RevocationResponse() {
        data class FailureInfo(
            val serial: BigInteger,
            val reason: PKIStatusInfo,
        )
    }
}