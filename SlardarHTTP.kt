package net.slardar.slardarHTTP

import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.net.URLEncoder
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager

class SlardarHTTP {
    class SlardarHTTPException(message: String, private val errorCode: Int) : Exception(message) {
        fun getErrorCode(): Int {
            return errorCode
        }
    }

    private class SlardarX509TrustManager(
        private val checkCertificate: Boolean,
        private val certSerialNumber: BigInteger? = null
    ) :
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
            } else if (checkCertificate) {
                if (chain == null) {
                    throw CertificateException("Server certificate chain is missing")
                }
                if (chain.isEmpty()) {
                    throw CertificateException("Server certificate chain length is 0")
                }

                try {
                    chain[0].checkValidity()
                } catch (e: java.lang.Exception) {
                    throw CertificateException(e)
                }
            }
        }

        override fun getAcceptedIssuers(): Array<X509Certificate>? {
            return null
        }
    }

    enum class Method {
        POST, GET
    }

    companion object {
        private const val TIME_OUT = 5000

        fun httpFormStringRequest(
            requestURL: String,
            method: Method,
            headers: HashMap<String, String>? = null,
            getArgs: HashMap<String, String>? = null,
            postArgs: HashMap<String, Any>? = null
        ): String {
            var newURL = requestURL
            if (getArgs != null) for (getArg in getArgs) {
                newURL += when (newURL) {
                    requestURL -> {
                        ("?" + URLEncoder.encode(getArg.key, "UTF-8") + "=" + URLEncoder.encode(
                            getArg.value,
                            "UTF-8"
                        ))
                    }
                    else -> {
                        ("&" + URLEncoder.encode(getArg.key, "UTF-8") + "=" + URLEncoder.encode(
                            getArg.value,
                            "UTF-8"
                        ))
                    }
                }
            }
            checkType(postArgs)
            val requestConnection: HttpURLConnection =
                getURLConnection(newURL, false, null) as HttpURLConnection
            var postTemp: File? = null
            if (postArgs.isNullOrEmpty()) {
                prepareHeader(requestConnection, headers, null)
                requestConnection.doInput = true
                requestConnection.doOutput = false
            } else {
                val boundary = boundaryBuilder()
                prepareHeader(requestConnection, headers, boundary)
                postTemp =
                    postBuilder(
                        postArgs,
                        boundary
                    )
                requestConnection.setRequestProperty("Content-Length", postTemp.length().toString())
            }
            if (method == Method.GET) {
                requestConnection.requestMethod = "GET"
                requestConnection.doInput = true
                requestConnection.doOutput = false
            } else {
                requestConnection.requestMethod = "POST"
                requestConnection.doInput = true
                requestConnection.doOutput = true
            }
            requestConnection.useCaches = false
            try {
                if (postTemp != null) {
                    val os = requestConnection.outputStream
                    os.write(postTemp.readBytes())
                    postTemp.delete()
                    os.flush()
                    os.close()
                }

                if (requestConnection.responseCode != 200) {
                    throw SlardarHTTPException(
                        requestConnection.responseMessage,
                        requestConnection.responseCode
                    )
                }
                val charset = getCharset(requestConnection)
                val isr = InputStreamReader(
                    requestConnection.inputStream,
                    charset
                )
                var responseText = ""
                var tmp = isr.readText()
                while (tmp.isNotEmpty()) {
                    responseText += tmp
                    tmp = isr.readText()
                }
                return responseText
            } catch (ex: SlardarHTTPException) {
                throw ex
            } catch (ex: java.lang.Exception) {
                throw SlardarHTTPException(
                    ex.message ?: "Unexpected error", -2
                )
            }
        }

        fun httpsFormStringRequest(
            requestURL: String,
            method: Method,
            headers: HashMap<String, String>? = null,
            getArgs: HashMap<String, String>? = null,
            postArgs: HashMap<String, Any>? = null,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): String {
            var newURL = requestURL
            if (getArgs != null) for (getArg in getArgs) {
                newURL += when (newURL) {
                    requestURL -> {
                        ("?" + URLEncoder.encode(getArg.key, "UTF-8") + "=" + URLEncoder.encode(
                            getArg.value,
                            "UTF-8"
                        ))
                    }
                    else -> {
                        ("&" + URLEncoder.encode(getArg.key, "UTF-8") + "=" + URLEncoder.encode(
                            getArg.value,
                            "UTF-8"
                        ))
                    }
                }
            }
            checkType(postArgs)
            val requestConnection: HttpsURLConnection =
                getURLConnection(
                    newURL,
                    checkCertificate,
                    certSerialNumber
                ) as HttpsURLConnection
            var postTemp: File? = null
            if (postArgs.isNullOrEmpty()) {
                prepareHeader(requestConnection, headers, null)
                requestConnection.doInput = true
                requestConnection.doOutput = false
            } else {
                val boundary = boundaryBuilder()
                prepareHeader(requestConnection, headers, boundary)
                postTemp =
                    postBuilder(
                        postArgs,
                        boundary
                    )
                requestConnection.setRequestProperty("Content-Length", postTemp.length().toString())
            }
            if (method == Method.GET) {
                requestConnection.requestMethod = "GET"
                requestConnection.doInput = true
                requestConnection.doOutput = false
                postTemp?.delete()
                postTemp = null
            } else {
                requestConnection.requestMethod = "POST"
                requestConnection.doInput = true
                requestConnection.doOutput = true
            }
            requestConnection.useCaches = false
            try {
                if (postTemp != null) {
                    val os = requestConnection.outputStream
                    os.write(postTemp.readBytes())
                    postTemp.delete()
                    os.flush()
                    os.close()
                }

                if (requestConnection.responseCode != 200) {
                    throw SlardarHTTPException(
                        requestConnection.responseMessage,
                        requestConnection.responseCode
                    )
                }
                val charset = getCharset(requestConnection)
                val isr = InputStreamReader(
                    requestConnection.inputStream,
                    charset
                )
                var responseText = ""
                var tmp = isr.readText()
                while (tmp.isNotEmpty()) {
                    responseText += tmp
                    tmp = isr.readText()
                }
                return responseText
            } catch (ex: SlardarHTTPException) {
                throw ex
            } catch (ex: java.lang.Exception) {
                throw SlardarHTTPException(
                    ex.message ?: "Unexpected error", -2
                )
            }
        }

        private fun postBuilder(postArgs: HashMap<String, Any>, boundary: String): File {
            val tmpFile: File = File.createTempFile(System.nanoTime().toString(), null)
            val fos = FileOutputStream(tmpFile)

            if (postArgs.isNotEmpty()) {
                for (post in postArgs) {
                    when (post.value) {
                        is String -> {
                            fos.write(
                                ("--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + URLEncoder.encode(
                                    post.value as String,
                                    "UTF-8"
                                ) + "\r\n").toByteArray(Charsets.UTF_8)
                            )
                        }
                        is File -> {
                            val postFile = (post.value as File)
                            fos.write(
                                "--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"filename=\"${postFile.name}\"\r\nContent-Type: ${URLConnection.guessContentTypeFromName(
                                    postFile.name
                                )} Content-Transfer-Encoding: binary\r\n\r\n".toByteArray(Charsets.UTF_8)
                            )
                            fos.write(postFile.readBytes())
                            fos.write("\r\n--${boundary}--\r\n".toByteArray(Charsets.UTF_8))
                        }
                        is ByteArray -> {
                            val postByteArray = (post.value as ByteArray)
                            fos.write(
                                "--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"; filename=\"${post.key + postByteArray.size.toString()}\"\r\nContent-Type: Unknown; Content-Transfer-Encoding: binary\r\n\r\n".toByteArray(
                                    Charsets.UTF_8
                                )
                            )
                            fos.write(postByteArray)
                            fos.write("\r\n--${boundary}--\r\n".toByteArray(Charsets.UTF_8))
                        }
                    }
                }
            }
            fos.flush()
            fos.close()
            return tmpFile
        }


        private fun getURLConnection(
            requestURL: String,
            checkCertificate: Boolean = false,
            certSerialNumber: BigInteger? = null
        ): URLConnection {
            val url = URL(requestURL)
            return if (requestURL.contains(Regex("^https:\\/\\/"))) {
                val sslContext = SSLContext.getInstance("SSL")
                if (checkCertificate || certSerialNumber != null) {
                    sslContext.init(
                        null,
                        arrayOf(SlardarX509TrustManager(checkCertificate, certSerialNumber)),
                        SecureRandom()
                    )
                } else {
                    sslContext.init(
                        null, arrayOf(SlardarX509TrustManager(false)),
                        SecureRandom()
                    )
                }
                val requestConnection = url.openConnection() as HttpsURLConnection
                requestConnection.sslSocketFactory = sslContext.socketFactory
                requestConnection.connectTimeout = TIME_OUT
                requestConnection
            } else {
                val requestConnection = url.openConnection() as HttpURLConnection
                requestConnection.connectTimeout = TIME_OUT
                requestConnection
            }
        }


        private fun prepareHeader(
            requestConnection: URLConnection,
            headers: HashMap<String, String>?,
            boundary: String?
        ) {
            var hasUA = false
            if (!headers.isNullOrEmpty()) {
                for (header in headers.iterator()) {
                    if (header.key.toLowerCase() == "user-agent") {
                        hasUA = true
                    } else if (header.key.toLowerCase() != "content-length") {
                        requestConnection.setRequestProperty(header.key, header.value)
                    }
                }
            }
            if (boundary != null)
                requestConnection.setRequestProperty(
                    "Content-Type",
                    "multipart/form-data; boundary=${boundary}"
                )
            if (!hasUA)
                requestConnection.setRequestProperty(
                    "User-Agent",
                    "Mozilla/5.0 Slardar HTTP Requester"
                )

        }

        private fun boundaryBuilder(): String {
            return "----SlardarHTTPRequesterBOUNDARY" + "%02x".format(System.currentTimeMillis())
        }

        private fun checkType(postArgs: HashMap<String, Any>?) {
            postArgs?.forEach {
                if (it.value !is String && it.value !is File && it.value !is ByteArray)
                    throw SlardarHTTPException(
                        "Only File, String adn ByteArray Class is supported, object type:" + it.value.javaClass.name,
                        -1
                    )
            }
        }

        private fun getCharset(requestConnection: URLConnection): Charset {
            var charsetText: String? = requestConnection.contentEncoding
            return if (requestConnection.contentEncoding == null) {
                charsetText = requestConnection.getHeaderField("content-type")
                if (charsetText == null) {
                    Charsets.UTF_8
                } else {
                    if (charsetText.contains("charset=")) {
                        val start = charsetText.indexOf("charset=", 0, true) + 8
                        var end = charsetText.indexOf(";", start, true)
                        if (end == -1) {
                            end = charsetText.length
                        }

                        Charset.forName(charsetText.substring(start, end))
                    } else {
                        Charsets.UTF_8
                    }
                }
            } else {
                Charset.forName(charsetText)
            }
        }
    }
}