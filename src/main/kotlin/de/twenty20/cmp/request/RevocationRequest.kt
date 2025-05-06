package de.twenty20.cmp.request

import de.twenty20.cmp.response.ResponseAnalyser
import de.twenty20.cmp.response.RevocationResponse
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1Integer
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.asn1.cmp.PKIStatus
import org.bouncycastle.asn1.cmp.RevDetails
import org.bouncycastle.asn1.cmp.RevRepContent
import org.bouncycastle.asn1.cmp.RevReqContent
import org.bouncycastle.asn1.crmf.CertTemplateBuilder
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.Extensions
import org.bouncycastle.cert.cmp.CMPException
import org.bouncycastle.cert.cmp.GeneralPKIMessage
import java.math.BigInteger
import java.security.cert.X509Certificate

/**
 *
 * @author Joscha Vack - twenty20
 */

class RevocationRequest(
    private val revocations: List<Revocation>,
    private val reason: CRLReason = CRLReason.lookup(CRLReason.unspecified),
    transactionId: ASN1OctetString? = null,
)  : BaseRequest<RevocationResponse>(transactionId) {
    override val requestType: Int = PKIBody.TYPE_REVOCATION_REQ

    constructor(
        vararg certificates: X509Certificate,
        reason: CRLReason = CRLReason.lookup(CRLReason.unspecified),
        transactionId: ASN1OctetString? = null
    ) : this(certificates.map(::Revocation), reason, transactionId)

    constructor(
        vararg revocations: Revocation,
        reason: CRLReason = CRLReason.lookup(CRLReason.unspecified),
        transactionId: ASN1OctetString? = null
    ) : this(revocations.toList(), reason, transactionId)

    data class Revocation(
        val serialNumber: BigInteger,
        val issuer: String,
    ) {
        constructor(certificate: X509Certificate) : this(certificate.serialNumber, certificate.issuerX500Principal.name)
    }

    override fun buildRequestBody(raCertificate: X509Certificate): ASN1Encodable {
        return RevReqContent(
            revocations.map {
                RevDetails(CertTemplateBuilder().apply {
                    setIssuer(X500Name(it.issuer))
                    setSerialNumber(ASN1Integer(it.serialNumber))
                }.build(), Extensions(Extension(Extension.reasonCode, false, reason.getEncoded())))
            }.toTypedArray()
        )
    }

    override fun ResponseAnalyser.handleResponseBody(
        response: GeneralPKIMessage
    ): RevocationResponse {
        validateContentType(response, PKIBody.TYPE_REVOCATION_REP)
        val content = response.body.content as RevRepContent
        val status = content.status

        if (status.size != revocations.size) {
            throw CMPException("Unexpected response size ${status.size} (expected ${revocations.size})")
        }

        val revokedSerials = mutableListOf<BigInteger>()
        val failedSerials = mutableListOf<RevocationResponse.Failure.FailureInfo>()
        for (i in status.indices) {
            val s = status[i]
            val sn = revocations[i].serialNumber
            if (s.status.toInt() == PKIStatus.GRANTED) {
                revokedSerials.add(sn)
            }
            else {
                failedSerials.add(RevocationResponse.Failure.FailureInfo(sn, s))
            }
        }

        if (failedSerials.isNotEmpty()) {
            return RevocationResponse.Failure(revokedSerials, failedSerials)
        }
        return RevocationResponse.Success(revokedSerials)
    }
}