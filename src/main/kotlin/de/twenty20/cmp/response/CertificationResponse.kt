package de.twenty20.cmp.response

import de.twenty20.cmp.request.CertType
import org.bouncycastle.asn1.ASN1OctetString
import java.math.BigInteger
import java.security.PrivateKey
import java.security.cert.X509Certificate

/**
 *
 * @author Joscha Vack - twenty20
 */

/**
 * Response to a successful certification request
 */
class CertificationResponse(
    val transactionId: ASN1OctetString,
    val requestIds: List<BigInteger>,
    val data: List<CertificateInfo>,
) : BaseResponse() {

    data class CertificateInfo(
        val type: CertType.CertUsage,
        val cert: X509Certificate,
        val revocationPassword: String,
        val chain: List<X509Certificate>,
        val privateKey: PrivateKey?,
    )
}