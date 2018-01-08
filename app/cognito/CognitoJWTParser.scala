package cognito

import java.security.InvalidParameterException
import java.util.Base64

import play.api.libs.json.{JsValue, Json}

object CognitoJWTParser {

  private val HEADER = 0
  private val PAYLOAD = 1
  private val SIGNATURE = 2
  private val JWT_PARTS = 3

  def getHeader(jwt: String): JsValue = if (validateJWT(jwt)) {
      val dec = Base64.getDecoder
      val sectionDecoded = dec.decode(jwt.split("\\.")(HEADER))
      val jwtSection = new String(sectionDecoded, "UTF-8")
      Json.parse(jwtSection)
    } else {
      throw new IllegalArgumentException("The JWT you passed is not the correct one")
    }

  def getPayload(jwt: String): JsValue = if (validateJWT(jwt)) {
      val dec = Base64.getDecoder
      val payload = jwt.split("\\.")(PAYLOAD)
      val sectionDecoded = dec.decode(payload)
      val jwtSection = new String(sectionDecoded, "UTF-8")
      Json.parse(jwtSection)
    } else {
      throw new IllegalArgumentException("The JWT you passed is not the correct one")
    }

  def getSignature(jwt: String): JsValue = if (validateJWT(jwt)) {
      val dec = Base64.getDecoder
      val sectionDecoded = dec.decode(jwt.split("\\.")(SIGNATURE))
      val jwtSection = new String(sectionDecoded, "UTF-8")
      Json.parse(jwtSection)
    } else {
      throw new IllegalArgumentException("The JWT you passed is not the correct one")
    }

  def getClaim(jwt: String, claim: String): Option[String] = (getPayload(jwt) \ claim).asOpt[String]

  def validateJWT(jwt: String): Boolean = {
    val jwtParts = jwt.split("\\.")
    if (jwtParts.length != JWT_PARTS) throw new InvalidParameterException("not a JSON Web Token")
    else true
  }

}
