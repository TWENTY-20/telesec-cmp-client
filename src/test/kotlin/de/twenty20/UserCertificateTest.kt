package de.twenty20

import de.twenty20.cmp.request.CertType
import de.twenty20.cmp.request.CertificationRequest
import de.twenty20.cmp.request.RevocationRequest
import de.twenty20.cmp.response.RevocationResponse
import org.bouncycastle.asn1.*
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNamesBuilder
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 *
 * @author Joscha Vack - twenty20
 */

class UserCertificateTest : TestBase() {
    @Test
    fun testSingleKey() {
        val kp = KEY_GEN.genKeyPair()
        val subject = buildUserSubject(
            subDomain = "SingleKey",
            firstName = "Max",
            lastName = "Mustermann",
            email = "max.musterman.rcitest@test.mvpn.telekom.de",
        )
        val pw = "test1234"

        val req = CertificationRequest(
            type = CertType.User.SingleKey,
            subject = subject,
            publicKey = kp.public,
            revocationPassword = pw
        )
        val res = CLIENT.submit(req)

        // validate response
        assertEquals(res.data.size, 1)

        val entry = res.data.first()
        assertNull(entry.privateKey)
        assertEquals(entry.revocationPassword, pw)
    }

    @Test
    fun testUserCertificate1WithServerSideKeygen() {
        val subject = buildUserSubject(
            subDomain = "SingleKey",
            firstName = "Max",
            lastName = "Mustermann",
            email = "max.musterman.rcitest@test.mvpn.telekom.de",
        )
        val req = CertificationRequest(
            type = CertType.User.SingleKey,
            subject = subject,
        )
        val res = CLIENT.submit(req)
        assertEquals(res.data.size, 1)

        val entry = res.data.first()
        assertNotNull(entry.privateKey)
    }

    @Test
    fun testUserCertificate2() {
        val kp = KEY_GEN.genKeyPair()
        val subject = buildUserSubject(
            subDomain = "Dualkey",
            firstName = "Max",
            lastName = "Mustermann",
            email = "max.musterman.rcitest@test.mvpn.telekom.de",
        )

        val req = CertificationRequest(
            type = CertType.User.DualKey,
            subject = subject,
            publicKey = kp.public,
        )
        val res = CLIENT.submit(req)

        assertEquals(res.data.size, 2)
    }

    @Test
    fun testUserCertificate3() {
        val kp = KEY_GEN.genKeyPair()
        val subject = buildUserSubject(
            subDomain = "TripleKey",
            firstName = "Max",
            lastName = "Mustermann",
            email = "max.musterman.rcitest@test.mvpn.telekom.de",
        )

        val mail = DERUTF8String("max.musterman.rcitest@test.mvpn.telekom.de")
        val subjectAlternativeName = GeneralNamesBuilder().apply {
            addName(
                GeneralName(
                    GeneralName.otherName, DERSequence(ASN1EncodableVector().apply {
                        add(ASN1ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"))
                        add(DERTaggedObject(true, 0, mail))
                    })
                )
            )
            addName(GeneralName(GeneralName.rfc822Name, mail))
        }.build()

        val req = CertificationRequest(
            type = CertType.User.TripleKey,
            subject = subject,
            publicKey = kp.public,
            subjectAlternative = subjectAlternativeName,
        )
        val res = CLIENT.submit(req)

        assertEquals(res.data.size, 3)
    }

    @Test
    fun testUserCertificateRevocation() {
        val subject = buildUserSubject(
            "Dualkey",
            firstName = "Max",
            lastName = "Mustermann",
            email = "max.musterman.rcitest@test.mvpn.telekom.de",
        )

        val req = CertificationRequest(
            type = CertType.User.DualKey,
            subject = subject,
        )
        val res = CLIENT.submit(req)

        // validate response
        assertEquals(res.data.size, 2)

        val revocationRequest = RevocationRequest(*res.data.map { it.cert }.toTypedArray())
        val revocationResponse = CLIENT.submit(revocationRequest)

        assertTrue(revocationResponse is RevocationResponse.Success)
        assertEquals(revocationResponse.revokedCertificates.size, res.data.size)
        for ((i, d) in res.data.withIndex()) {
            assertEquals(revocationResponse.revokedCertificates[i], d.cert.serialNumber)
        }
    }

    @Suppress("SameParameterValue")
    private fun buildUserSubject(
        subDomain: String,
        firstName: String,
        lastName: String,
        email: String,
    ): X500Name = X500NameBuilder().apply {
        addRDN(BCStyle.GIVENNAME, firstName)
        addRDN(BCStyle.SURNAME, lastName)
        addRDN(BCStyle.CN, "$firstName $lastName")
        addRDN(BCStyle.E, email)

        addRDN(BCStyle.ST, "Nordrhein-Westfalen")
        addRDN(BCStyle.O, "Deutsche Telekom AG")
        addRDN(BCStyle.L, "Bonn")
        addRDN(BCStyle.C, "DE")

        addRDN(BCStyle.OU, "test.mvpn.telekom.de")
        addRDN(BCStyle.OU, subDomain)
    }.build()
}