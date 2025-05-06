package de.twenty20.cmp.request

import de.twenty20.cmp.response.BaseResponse
import de.twenty20.cmp.response.ResponseAnalyser
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.cmp.PKIBody
import org.bouncycastle.cert.cmp.CMPException
import org.bouncycastle.cert.cmp.GeneralPKIMessage
import java.security.cert.X509Certificate


/**
 * Base class for PKI requests
 *
 * @param transactionId: (Optional) current transaction id (https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.1)
 */
abstract class BaseRequest<T : BaseResponse>(
    val transactionId: ASN1OctetString?
) {

    /**
     * PKI request type
     * @see PKIBody
     */
    abstract val requestType: Int

    /**
     * Build correct PKI body as described here: https://datatracker.ietf.org/doc/html/rfc4210#section-5.1.2
     */
    abstract fun buildRequestBody(raCertificate: X509Certificate): ASN1Encodable

    /**
     * Parse CA response body
     */
    abstract fun ResponseAnalyser.handleResponseBody(response: GeneralPKIMessage): T

    protected fun validateContentType(response: GeneralPKIMessage, type: Int) {
        val body = response.body
        if (body.type != type) {
            throw CMPException("Unexpected response type ${body.type} (expected $type)") // See PKIBody types
        }
    }
}

