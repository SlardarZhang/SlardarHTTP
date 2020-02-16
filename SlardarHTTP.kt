package net.slardar.ndk

import java.io.File
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.collections.ArrayList

/*
GET /test.php HTTP/1.1
Host: 192.168.1.101
Connection: keep-alive
Upgrade-Insecure-Requests: 1
DNT: 1
User-Agent: Mozilla/5.0 (Linux; Android 8.0.0; H8166) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.99 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,* / *;q=0.8,application/signed-exchange;v=b3;q=0.9
                                                                                  should remove space
Referer: http://192.168.1.101/
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
*/

/*

POST /test.php HTTP/1.1
Host: 192.168.1.101
Connection: keep-alive
Content-Length: 138
Cache-Control: max-age=0
Origin: http://192.168.1.101
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryGcy33s2mlfhv5b6d
User-Agent: Mozilla/5.0 (Linux; Android 8.0.0; H8166) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.99 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,* / *;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://192.168.1.101/test.php
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8

------WebKitFormBoundaryGcy33s2mlfhv5b6d
Content-Disposition: form-data; name="usn"
 */
class SlardarHTTP {
    class SlardarHTTPException(message: String, private val errorCode: Int) : Exception(message) {
        fun getErrorCode(): Int {
            return errorCode
        }
    }

    class SlardarX509TrustManager(private val certSerialNumber: BigInteger? = null) :
        X509TrustManager {

        override fun checkClientTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (certSerialNumber != null) {
                if (chain != null) {
                    var found = false
                    for (chain_ in chain) {
                        if (chain_.serialNumber.compareTo(certSerialNumber) == 0)
                            found = true
                    }
                    if (!found)
                        throw CertificateException("Client certificate verify failed")
                } else {
                    throw CertificateException("Client certificate chain is missing")
                }
            }
        }

        override fun checkServerTrusted(chain: Array<out X509Certificate>?, authType: String?) {
            if (certSerialNumber != null) {
                if (chain != null) {
                    var found = false
                    for (chain_ in chain) {
                        if (chain_.serialNumber.compareTo(certSerialNumber) == 0)
                            found = true
                    }
                    if (!found)
                        throw CertificateException("Server certificate verify failed")
                } else {
                    throw CertificateException("Server certificate chain is missing")
                }
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }
    }

    companion object {
        private const val TIME_OUT = 5000

        fun httpGetStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            getArgs: HashMap<String, String>?
        ): String {
            return httpPostGetFormStringRequest(requestURL, header, getArgs, null)
        }

        fun httpPostGetFormStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            getArgs: HashMap<String, String>?,
            postArgs: HashMap<String, Objects>?
        ): String {
            var newURL = requestURL
            if (getArgs != null) for (getArg in getArgs) {
                newURL += when (newURL) {
                    requestURL -> {
                        ("?" + getArg.key + "=" + getArg.value)
                    }
                    else -> {
                        ("&" + getArg.key + "=" + getArg.value)
                    }
                }
            }
            return httpPostFormStringRequest(newURL, header, postArgs)
        }

        fun httpPostFormStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            postArgs: HashMap<String, Objects>?
        ): String {
            return ""
        }

        fun httpsGetStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            getArgs: HashMap<String, String>?,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): String {
            return httpsPostGetFormStringRequest(
                requestURL,
                header,
                getArgs,
                null,
                checkCertificate,
                certSerialNumber
            )
        }

        fun httpsPostGetFormStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            getArgs: HashMap<String, String>?,
            postArgs: HashMap<String, Objects>?,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): String {
            var newURL = requestURL
            if (getArgs != null) for (getArg in getArgs) {
                newURL += when (newURL) {
                    requestURL -> {
                        ("?" + getArg.key + "=" + getArg.value)
                    }
                    else -> {
                        ("&" + getArg.key + "=" + getArg.value)
                    }
                }
            }
            return httpsPostFormStringRequest(
                newURL,
                header,
                postArgs,
                checkCertificate,
                certSerialNumber
            )
        }

        fun httpsPostFormStringRequest(
            requestURL: String,
            header: HashMap<String, String>?,
            postArgs: HashMap<String, Objects>?,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): String {
            postArgs?.forEach {
                if (it.value.javaClass.name != String::javaClass.name && it.value.javaClass.name != File::javaClass.name)
                    throw SlardarHTTP("Only file and string is supported", 0)
            }
            val requestConnection: HttpsURLConnection =
                getURLConnection(
                    requestURL,
                    checkCertificate,
                    certSerialNumber
                ) as HttpsURLConnection
            requestConnection.requestMethod = "POST"
            if (!postArgs.isNullOrEmpty()) {
                requestConnection.setRequestProperty(
                    "Content-Type",
                    "application/x-www-form-urlencoded"
                )
            }



            return ""
        }


        private fun getURLConnection(
            requestURL: String,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): URLConnection {
            val url = URL(requestURL)
            return if (requestURL.contains("^https:\\/\\/")) {
                val sslContext = SSLContext.getInstance("SSL")
                if (checkCertificate && certSerialNumber != null) {
                    sslContext.init(
                        null,
                        arrayOf(SlardarX509TrustManager(certSerialNumber)),
                        SecureRandom()
                    )
                } else {
                    sslContext.init(
                        null,
                        arrayOf(SlardarX509TrustManager(null)),
                        SecureRandom()
                    )
                }
                val requestConnection = url.openConnection() as HttpsURLConnection
                requestConnection.sslSocketFactory = sslContext.socketFactory
                requestConnection
            } else {
                val connection = url.openConnection() as HttpURLConnection
                connection.connectTimeout = TIME_OUT
                connection
            }
        }


        private fun perparHeader(
            requestConnection: URLConnection,
            header: HashMap<String, String>?
        ) {
            val headerKeys: ArrayList<String> = ArrayList()
            header?.keys?.toList()?.forEach {
                headerKeys.add(it.toLowerCase())
            }

            val ua: String = if (headerKeys.contains("user-agent")) {
                header?.get("user-agent") ?: header?.get("User-Agent") ?: "Slardar HTTP Requester"
            } else {
                "Slardar HTTP Requester"
            }

            requestConnection.setRequestProperty("User-Agent", ua)
        }
    }
}