package net.slardar.slardarhttp.exception

import org.json.JSONObject

@Suppress("MemberVisibilityCanBePrivate", "CanBeParameter")
class SlardarHTTPJSONException(val jsonMessage: JSONObject, private val errorCode: Int) :
    Exception(jsonMessage.toString()) {
    fun getErrorCode(): Int {
        return errorCode
    }
}
