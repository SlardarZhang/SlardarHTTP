package net.slardar.slardarHTTP

import android.annotation.SuppressLint
import org.json.JSONObject
import java.io.File
import java.io.OutputStream
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLConnection
import java.net.URLEncoder
import java.nio.charset.Charset
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.*
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.X509TrustManager
import kotlin.collections.HashMap

@Suppress("unused", "MemberVisibilityCanBePrivate")
class SlardarHTTP {
	class SlardarHTTPException(message: String, private val errorCode: Int) : Exception(message) {
		fun getErrorCode(): Int {
			return errorCode
		}
	}

	@Suppress("MemberVisibilityCanBePrivate", "CanBeParameter")
	class SlardarHTTPJSONException(val jsonMessage: JSONObject, private val errorCode: Int) :
		Exception(jsonMessage.toString()) {
		fun getErrorCode(): Int {
			return errorCode
		}
	}

	class CookiesString(val cookies: HashMap<String, String>, val text: String)

	@SuppressLint("CustomX509TrustManager")
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
			postArgs: HashMap<String, Any>? = null,
			cookies: HashMap<String, String>? = null,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): String {
			val requestConnection =
				getPostResponseStream(
					requestURL,
					method,
					headers,
					getArgs,
					postArgs,
					cookies,
					checkCertificate,
					certSerialNumber
				)

			val charset = getCharset(requestConnection)
			val scanner = Scanner(requestConnection.inputStream, charset.name())
			var responseText = ""
			while (scanner.hasNextLine()) {
				responseText += scanner.nextLine() + "\r\n"
			}
			requestConnection.inputStream.close()

			return responseText
		}

		fun httpFormStringRequestWithCookies(
			requestURL: String,
			method: Method,
			headers: HashMap<String, String>? = null,
			getArgs: HashMap<String, String>? = null,
			postArgs: HashMap<String, Any>? = null,
			cookies: HashMap<String, String>? = null,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): CookiesString {
			val requestConnection =
				getPostResponseStream(
					requestURL,
					method,
					headers,
					getArgs,
					postArgs,
					cookies,
					checkCertificate,
					certSerialNumber
				)

			val charset = getCharset(requestConnection)
			val scanner = Scanner(requestConnection.inputStream, charset.name())
			var responseText = ""
			while (scanner.hasNextLine()) {
				responseText += scanner.nextLine() + "\r\n"
			}
			requestConnection.inputStream.close()
			val responseCookies = HashMap<String, String>()
			requestConnection.headerFields.forEach { (headerName, headerValue) ->
				if (headerName == "Set-Cookie") {
					headerValue.forEach { setCookieValue ->
						val cookieValue = setCookieValue.split(";")[0]
						val cookieValueSpited = cookieValue.split("=")
						responseCookies[cookieValueSpited[0]] = cookieValueSpited[1]
					}
				}
			}
			return CookiesString(responseCookies, responseText)
		}

		fun httpFormJSONRequest(
			requestURL: String,
			method: Method,
			headers: HashMap<String, String>? = null,
			getArgs: HashMap<String, String>? = null,
			postArgs: HashMap<String, Any>? = null,
			cookies: HashMap<String, String>? = null,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): JSONObject {

			try {
				return JSONObject(
					httpFormStringRequest(
						requestURL,
						method,
						headers,
						getArgs,
						postArgs,
						cookies,
						checkCertificate,
						certSerialNumber
					)
				)
			} catch (slardarException: SlardarHTTPException) {
				val resultJSON = try {
					JSONObject(slardarException.message!!)
				} catch (ex: java.lang.Exception) {
					throw slardarException
				}
				throw SlardarHTTPJSONException(resultJSON, slardarException.getErrorCode())
			}
		}

		fun httpFormJSONRequestWithCookies(
			requestURL: String,
			method: Method,
			headers: HashMap<String, String>? = null,
			getArgs: HashMap<String, String>? = null,
			postArgs: HashMap<String, Any>? = null,
			cookies: HashMap<String, String>? = null,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): JSONObject {
			try {
				val response = httpFormStringRequestWithCookies(
					requestURL,
					method,
					headers,
					getArgs,
					postArgs,
					cookies,
					checkCertificate,
					certSerialNumber
				)
				val returnJSONObject = JSONObject()
				returnJSONObject.put("response", JSONObject(response.text))
				val responseCookies = JSONObject()
				response.cookies.forEach { (name, value) ->
					responseCookies.put(name, value)
				}
				returnJSONObject.put("cookies", responseCookies)
				return returnJSONObject
			} catch (slardarException: SlardarHTTPException) {
				val resultJSON = try {
					JSONObject(slardarException.message!!)
				} catch (ex: java.lang.Exception) {
					throw slardarException
				}
				throw SlardarHTTPJSONException(resultJSON, slardarException.getErrorCode())
			}
		}

		private fun postContentLength(postArgs: HashMap<String, Any>, boundary: String): Long {
			var contentLength: Long = 0
			var headerString = ""

			if (postArgs.isNotEmpty()) {
				for (post in postArgs) {
					when (post.value) {
						is String -> {
							headerString += "--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + post.value as String + "\r\n"
						}
						is Number -> {
							headerString += "--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + (post.value as Number).toString() + "\r\n"
						}
						is File -> {
							val postFile = (post.value as File)
							headerString += (
									"--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"; filename=\"${postFile.name}\"\r\nContent-Type: ${
										URLConnection.guessContentTypeFromName(
											postFile.name
										)
									}; Content-Transfer-Encoding: binary\r\n\r\n")
							contentLength += postFile.length()
							headerString += "\r\n--${boundary}--\r\n"
						}
						is ByteArray -> {
							val postByteArray = (post.value as ByteArray)
							headerString += "--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"; filename=\"${
								post.key + postByteArray.hashCode().toString()
							}\"\r\nContent-Type: Unknown; Content-Transfer-Encoding: binary\r\n\r\n"
							contentLength += postByteArray.size
							headerString += "\r\n--${boundary}--\r\n"
						}
					}
				}
			}
			contentLength += (headerString.toByteArray(Charsets.UTF_8)).size
			return contentLength
		}

		private fun postWriter(os: OutputStream, postArgs: HashMap<String, Any>, boundary: String) {
			if (postArgs.isNotEmpty()) {
				for (post in postArgs) {
					when (post.value) {
						is String -> {
							os.write(
								("--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + post.value as String + "\r\n").toByteArray(
									Charsets.UTF_8
								)
							)
							os.flush()
						}
						is Number -> {
							os.write(
								("--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n" + (post.value as Number).toString() + "\r\n").toByteArray(
									Charsets.UTF_8
								)
							)
							os.flush()
						}
						is File -> {
							val postFile = (post.value as File)
							os.write(
								(
										"--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"; filename=\"${postFile.name}\"\r\nContent-Type: ${
											URLConnection.guessContentTypeFromName(
												postFile.name
											)
										}; Content-Transfer-Encoding: binary\r\n\r\n").toByteArray(
									Charsets.UTF_8
								)
							)
							os.write(postFile.readBytes())
							os.write(("\r\n--${boundary}--\r\n").toByteArray(Charsets.UTF_8))
							os.flush()
						}
						is ByteArray -> {
							val postByteArray = (post.value as ByteArray)
							os.write(
								("--${boundary}\r\nContent-Disposition: form-data; name=\"${post.key}\"; filename=\"${
									post.key + postByteArray.hashCode().toString()
								}\"\r\nContent-Type: Unknown; Content-Transfer-Encoding: binary\r\n\r\n").toByteArray(
									Charsets.UTF_8
								)
							)
							os.write(postByteArray)
							os.write(("\r\n--${boundary}--\r\n").toByteArray(Charsets.UTF_8))
							os.flush()
						}
					}
				}
			}
			os.close()
		}

		private fun getHTTPConnection(
			requestURL: String,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): HttpURLConnection {
			return when (val requestConnection = URL(requestURL).openConnection()) {
				is HttpsURLConnection -> {
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
					requestConnection.sslSocketFactory = sslContext.socketFactory
					requestConnection.connectTimeout = TIME_OUT
					requestConnection
				}
				is HttpURLConnection -> {
					requestConnection.connectTimeout = TIME_OUT
					requestConnection
				}
				else -> {
					throw SlardarHTTPException("Unknown URL connection type", -3)
				}
			}
		}

		private fun prepareGetURL(
			requestURLString: String,
			getArgs: HashMap<String, String>
		): String {
			val requestURL = URL(requestURLString)
			val requestURLBase = requestURL.protocol + "://" + requestURL.host
			var newURL = requestURLString
			for (getArg in getArgs) {
				newURL += when (newURL) {
					requestURLString -> {
						if (requestURLBase == newURL) {
							("/?" + URLEncoder.encode(
								getArg.key,
								"UTF-8"
							) + "=" + URLEncoder.encode(
								getArg.value,
								"UTF-8"
							))
						} else {
							("?" + URLEncoder.encode(
								getArg.key,
								"UTF-8"
							) + "=" + URLEncoder.encode(
								getArg.value,
								"UTF-8"
							))
						}
					}
					else -> {
						("&" + URLEncoder.encode(getArg.key, "UTF-8") + "=" + URLEncoder.encode(
							getArg.value,
							"UTF-8"
						))
					}
				}
			}
			return newURL
		}

		private fun prepareHeader(
			requestConnection: URLConnection,
			headers: HashMap<String, String>?,
			cookies: HashMap<String, String>?,
			boundary: String?
		) {
			var hasUA = false
			var hasLanguage = false
			if (!headers.isNullOrEmpty()) {
				for (header in headers.iterator()) {
					when (header.key.lowercase(Locale.getDefault())) {
						"user-agent" -> {
							hasUA = true
						}
						"accept-language" -> {
							hasLanguage = true
						}
					}
					if (header.key.lowercase(Locale.getDefault()) != "content-length") {
						requestConnection.setRequestProperty(header.key, header.value)
					}
				}
			}
			if (!cookies.isNullOrEmpty()) {
				var cookieString = ""
				for (cookie in cookies.iterator()) {
					cookieString += "${cookie.key}=${cookie.value}; "
				}
				if (cookieString.isNotBlank()) {
					cookieString = cookieString.substring(0, cookieString.length - 2)
				}
				requestConnection.setRequestProperty("cookie", cookieString)
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
			if (!hasLanguage) {
				requestConnection.setRequestProperty(
					"Accept-Language",
					Locale.getDefault().toLanguageTag()
				)
			}

		}

		private fun boundaryBuilder(): String {
			return "----SlardarHTTPRequesterBOUNDARY" + "%02x".format(System.currentTimeMillis())
		}

		private fun checkType(postArgs: HashMap<String, Any>?) {
			postArgs?.forEach {
				if (it.value !is String && it.value !is File && it.value !is ByteArray && it.value !is Number)
					throw SlardarHTTPException(
						"Only File, String, Number and ByteArray Class is supported, object type:" + it.value.javaClass.name,
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

		private fun getPostResponseStream(
			requestURL: String,
			method: Method,
			headers: HashMap<String, String>? = null,
			getArgs: HashMap<String, String>? = null,
			postArgs: HashMap<String, Any>? = null,
			cookies: HashMap<String, String>? = null,
			checkCertificate: Boolean = false,
			certSerialNumber: BigInteger? = null
		): HttpURLConnection {
			try {
				checkType(postArgs)
				val newURL = if (getArgs.isNullOrEmpty()) {
					requestURL
				} else {
					prepareGetURL(requestURL, getArgs)
				}
				val requestConnection =
					getHTTPConnection(newURL, checkCertificate, certSerialNumber)
				val boundary = boundaryBuilder()
				prepareHeader(requestConnection, headers, cookies, boundary)
				if (method == Method.GET) {
					requestConnection.requestMethod = "GET"
					requestConnection.doInput = true
					requestConnection.doOutput = false
					requestConnection.useCaches = false
				} else {
					requestConnection.requestMethod = "POST"
					requestConnection.doInput = true
					requestConnection.doOutput = true
					requestConnection.useCaches = false
					if (postArgs.isNullOrEmpty()) {
						requestConnection.setRequestProperty("Content-Length", "0")
					} else {
						requestConnection.setRequestProperty(
							"Content-Length",
							postContentLength(postArgs, boundary).toString()
						)
						postWriter(requestConnection.outputStream, postArgs, boundary)
					}
				}
				if (requestConnection.responseCode != 200) {
					val charset = getCharset(requestConnection)
					val scanner = Scanner(requestConnection.errorStream, charset.name())
					var responseText = ""
					while (scanner.hasNextLine()) {
						responseText += scanner.nextLine() + "\r\n"
					}
					requestConnection.errorStream.close()
					if (responseText.isNotEmpty()) {
						throw SlardarHTTPException(
							responseText,
							requestConnection.responseCode
						)
					} else {
						throw SlardarHTTPException(
							requestConnection.responseMessage,
							requestConnection.responseCode
						)
					}

				}
				return requestConnection
			} catch (ex: SlardarHTTPException) {
				throw ex
			} catch (ex: java.lang.Exception) {
				throw SlardarHTTPException(
					ex.message ?: "Unexpected error", -2
				)
			}
		}
	}
}