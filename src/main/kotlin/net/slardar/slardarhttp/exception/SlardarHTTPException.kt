package net.slardar.slardarhttp.exception

class SlardarHTTPException(message: String, private val errorCode: Int) : Exception(message) {
    fun getErrorCode(): Int {
        return errorCode
    }
}