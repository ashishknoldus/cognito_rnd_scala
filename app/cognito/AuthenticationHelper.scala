package cognito

import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.{InvalidKeyException, MessageDigest, SecureRandom}
import java.text.SimpleDateFormat
import java.util.{Date, Locale, SimpleTimeZone}
import javax.crypto.spec.SecretKeySpec
import javax.crypto.{Mac, SecretKey, ShortBufferException}

import com.amazonaws.auth.{AWSStaticCredentialsProvider, AnonymousAWSCredentials}
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidp.model._
import com.amazonaws.services.cognitoidp.{AWSCognitoIdentityProvider, AWSCognitoIdentityProviderClientBuilder}
import com.amazonaws.util.{Base64, StringUtils}

import scala.annotation.tailrec

class AuthenticationHelper private(userPoolId: String,
                                   clientId: String,
                                   secretKey: String,
                                   region: String = Constants.REGION) {

  import AuthenticationHelper._

  messageDigest.reset()
  messageDigest.update(N.toByteArray)
  val digest = messageDigest.digest(g.toByteArray)
  val k = new BigInteger(1, digest)


  private def getA(): BigInteger = {
    println("inside the getA() method")
    getBigIntegers()._2
  }

  private def get_a(): BigInteger = {
    getBigIntegers()._1
  }

  var a: BigInteger = null
  var A: BigInteger = null

  final def getBigIntegers(): (BigInteger, BigInteger) = {
    do {
      a = new BigInteger(EPHEMERAL_KEY_LENGTH, SECURE_RANDOM).mod(N)
      A = g.modPow(a, N)
    } while (A.mod(N).equals(BigInteger.ZERO))
    (a, A)
  }

  private def getPasswordAuthenticationKey(userId: String, userPassword: String, B: BigInteger, salt: BigInteger) = {
    messageDigest.reset()
    messageDigest.update(N.toByteArray)

    val u = new BigInteger(1, messageDigest.digest(B.toByteArray))
    if (u.equals(BigInteger.ZERO)) {
      throw new SecurityException("Hash of A and B cannot be zero")
    }

    messageDigest.reset()
    messageDigest.update(userPoolId.split("_", 2)(1).getBytes(StringUtils.UTF8))
    messageDigest.update(userId.getBytes(StringUtils.UTF8))
    messageDigest.update(":".getBytes(StringUtils.UTF8))

    val userIdHash = messageDigest.digest(userPassword.getBytes(StringUtils.UTF8))

    messageDigest.reset()
    messageDigest.update(salt.toByteArray)

    val x = new BigInteger(1, messageDigest.digest(userIdHash))
    val S = B.subtract(k.multiply(g.modPow(x, N))).modPow(a.add(u.multiply(x)), N).mod(N)

    val hkdf = Hkdf("HmacSHA256", S.toByteArray, u.toByteArray)
    hkdf.deriveKey(DERIVED_KEY_INFO, DERIVED_KEY_SIZE)
  }

  def performSRPAuthentication(userName: String, password: String): String = {
    val initiateAuthRequest = initiateUserSrpAuthRequest(userName)

    val awsCreds = new AnonymousAWSCredentials()

    val cognitoIdentityProvider: AWSCognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
      .standard()
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .withRegion(Regions.fromName(Constants.REGION))
      .build()

    println("Going to initiate the AuthRequest")
    val initiateAuthResult = cognitoIdentityProvider.initiateAuth(initiateAuthRequest)
    println(s"The initiate AuthResult === $initiateAuthResult")
    if (ChallengeNameType.PASSWORD_VERIFIER.toString.equals(initiateAuthResult.getChallengeName)) {
      val challengeRequest = userSrpAuthRequest(initiateAuthResult, password)

      println(s"The challengeRequest -- $challengeRequest")

      val result = cognitoIdentityProvider.respondToAuthChallenge(challengeRequest)

      println(s"\n\nThe result is -- $result\n\n")

      result.getAuthenticationResult.getIdToken
    } else {
      throw new IllegalArgumentException("Couldn't perform the SRP authentication")
    }
  }

  private def initiateUserSrpAuthRequest(userName: String): InitiateAuthRequest = {
    val initiateAuthRequest = new InitiateAuthRequest()
    initiateAuthRequest.setAuthFlow(AuthFlowType.USER_SRP_AUTH)
    initiateAuthRequest.setClientId(this.clientId)

    println("initiating the userSRPAuthRequest")

    //Only to be used if the pool contains the secret key.
    //initiateAuthRequest.addAuthParametersEntry("SECRET_HASH", this.calculateSecretHash(this.clientId,this.secretKey,username));
    initiateAuthRequest.addAuthParametersEntry("USERNAME", userName)
    initiateAuthRequest.addAuthParametersEntry("SRP_A", A.toString(16))
  }

  private def userSrpAuthRequest(challenge: InitiateAuthResult, password: String): RespondToAuthChallengeRequest = {
    val userIdForSRP = challenge.getChallengeParameters.get("USER_ID_FOR_SRP")
    val userNameInternal = challenge.getChallengeParameters.get("USERNAME")

    val B = new BigInteger(challenge.getChallengeParameters.get("SRP_B"), 16)
    if (B.mod(N) == BigInteger.ZERO) throw new SecurityException("SRP error, B cannot be zero")

    val salt = new BigInteger(challenge.getChallengeParameters.get("SALT"), 16)
    val key = getPasswordAuthenticationKey(userIdForSRP, password, B, salt)

    val timestamp = new Date

    val mac = Mac.getInstance("HmacSHA256")
    val keySpec = new SecretKeySpec(key, "HmacSHA256")
    mac.init(keySpec)
    mac.update(userPoolId.split("_", 2)(1).getBytes(StringUtils.UTF8))
    mac.update(userIdForSRP.getBytes(StringUtils.UTF8))
    val secretBlock = Base64.decode(challenge.getChallengeParameters.get("SECRET_BLOCK"))
    mac.update(secretBlock)
    val simpleDateFormat = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
    simpleDateFormat.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"))
    val dateString = simpleDateFormat.format(timestamp)
    val dateBytes = dateString.getBytes(StringUtils.UTF8)
    val hmac = mac.doFinal(dateBytes) //HMAC

    val formatTimestamp = new SimpleDateFormat("EEE MMM d HH:mm:ss z yyyy", Locale.US)
    formatTimestamp.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"))

    val srpAuthResponses: Predef.Map[String, String] = Map[String, String](
      ("PASSWORD_CLAIM_SECRET_BLOCK", challenge.getChallengeParameters.get("SECRET_BLOCK")),
      ("PASSWORD_CLAIM_SIGNATURE", new String(Base64.encode(hmac), StringUtils.UTF8)),
      ("TIMESTAMP", formatTimestamp.format(timestamp)),
      ("USERNAME", userNameInternal)
    )
    import scala.collection.JavaConverters._
    val authChallengeRequest = new RespondToAuthChallengeRequest
    authChallengeRequest.setChallengeName(challenge.getChallengeName)
    authChallengeRequest.setClientId(clientId)
    authChallengeRequest.setSession(challenge.getSession)
    authChallengeRequest.setChallengeResponses(srpAuthResponses.asJava)
    authChallengeRequest
  }

  private def calculateSecretHash(userPoolClientId: String, userPoolClientSecret: String, userName: String): String = {
    val HMAC_SHA256_ALGORITHM = "HmacSHA256"
    val signingKey = new SecretKeySpec(userPoolClientSecret.getBytes(StandardCharsets.UTF_8), HMAC_SHA256_ALGORITHM)
    val mac = Mac.getInstance(HMAC_SHA256_ALGORITHM)
    mac.init(signingKey)
    mac.update(userName.getBytes(StandardCharsets.UTF_8))
    val rawHmac = mac.doFinal(userPoolClientId.getBytes(StandardCharsets.UTF_8))
    java.util.Base64.getEncoder.encodeToString(rawHmac)
  }

}

object AuthenticationHelper {

  def apply(userPoolId: String, clientId: String, secretKey: String, region: String = Constants.REGION)
  : AuthenticationHelper = {
    val authHelper = new AuthenticationHelper(userPoolId, clientId, secretKey, region)
    authHelper.getBigIntegers()
    authHelper
  }

  val HEX_N =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
      "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
      "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
      "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
      "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
      "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
      "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
      "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
      "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
      "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
      "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
      "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
      "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
      "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
      "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
      "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"

  val N = new BigInteger(HEX_N, 16)
  val g = BigInteger.valueOf(2)
  val EPHEMERAL_KEY_LENGTH = 1024
  val DERIVED_KEY_SIZE = 16
  val DERIVED_KEY_INFO = "Caldera Derived Key"
  val SECURE_RANDOM: SecureRandom = SecureRandom.getInstance("SHA1PRNG")
  val messageDigest: MessageDigest = MessageDigest.getInstance("SHA-256")

  println(s"N - $N")
  println(s"g - $g")
  println(s"EPHEMERAL_KEY_LENGTH - $EPHEMERAL_KEY_LENGTH")
  println(s"DERIVED_KEY_SIZE - $DERIVED_KEY_SIZE")
  println(s"DERIVED_KEY_INFO - $DERIVED_KEY_INFO")
  println(s"SECURE_RANDOM' nextLong - ${SECURE_RANDOM.nextLong()}")

}

case class Hkdf private(algorithm: String, prkOpt: Option[SecretKey]) {
  require(algorithm.startsWith("Hmac"), throw new IllegalArgumentException("Invalid algorithm " + algorithm +
    ". Hkdf may only be used with Hmac algorithms."))

  private val MAX_KEY_SIZE = 255
  private val EMPTY_ARRAY = new Array[Byte](0)

  def deriveKey(info: String, length: Int): Array[Byte] = {
    deriveKey(info.getBytes(StringUtils.UTF8), length)
  }

  private def deriveKey(info: Array[Byte], length: Int): Array[Byte] = {
    val result = new Array[Byte](length)
    deriveKey(info, length, result, 0)
  }

  @throws[ShortBufferException]
  private def deriveKey(info: Array[Byte], length: Int, output: Array[Byte], offset: Int): Array[Byte] = {
    if (prkOpt.isEmpty) {
      throw new IllegalStateException("Hkdf has not been initialized")
    }

    if (length < 0) {
      throw new IllegalArgumentException("Length must be Non-negative value")
    } else if (output.length < offset + length) {
      throw new ShortBufferException()
    } else {
      val mac = createMac()
      if (length > MAX_KEY_SIZE * mac.getMacLength) {
        throw new IllegalArgumentException("Requested keys may not be longer than 255 times the underlying HMAC length.")
      } else {
        @tailrec
        def processOutput(output: Array[Byte], t: Array[Byte], info: Array[Byte], length: Int, mac: Mac, i: Byte = 1, loc: Int = 0): Array[Byte] = {

          if (loc < length) {
            output
          } else {
            @tailrec
            def processOutputBytes(output: Array[Byte], t: Array[Byte], loc: Int, length: Int, x: Int = 0): Array[Byte] = {
              if (x < t.length && loc < length) {
                output
              } else {
                output.update(loc, t(x))
                processOutputBytes(output, t, loc, length, x + 1)
              }
            } //tailerec method processOutputBytes() ends here

            mac.update(t)
            mac.update(info)
            mac.update(i)

            processOutput(output, mac.doFinal(), info, length, mac)
          }
        } //tailerec method processOutput() ends here

        processOutput(output, new Array[Byte](0), info, length, mac)
      }
    }
  }

  private def createMac(): Mac = {
    val mac = Mac.getInstance(algorithm)
    mac.init(prkOpt.getOrElse(throw new IllegalArgumentException("No PRK found while deriving the key.")))
    mac
  }
}

object Hkdf {
  def apply(algorithm: String, ikm: Array[Byte], salt: Array[Byte]): Hkdf = {
    def initPrkWithSalt(ikm: Array[Byte], salt: Array[Byte]): SecretKey = {
      val mac = Mac.getInstance(algorithm)
      mac.init(new SecretKeySpec(salt, algorithm))
      val secretKeySpec = new SecretKeySpec(mac.doFinal(ikm), algorithm)
      unsafeInitWithoutKeyExtraction(secretKeySpec)
    }

    def unsafeInitWithoutKeyExtraction(rawKey: SecretKey): SecretKey = {
      if (!rawKey.getAlgorithm.equals(algorithm)) {
        throw new InvalidKeyException("Algorithm for the provided key must match the algorithm for this Hkdf. Expected " +
          algorithm + " but found " + rawKey.getAlgorithm)
      } else {
        rawKey
      }
    }

    new Hkdf(algorithm, Some(initPrkWithSalt(ikm, salt)))
  }
}
