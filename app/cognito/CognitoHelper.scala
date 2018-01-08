package cognito

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import cognito.Constants._
import com.amazonaws.auth.{AWSStaticCredentialsProvider, AnonymousAWSCredentials}
import com.amazonaws.regions.Regions
import com.amazonaws.services.cognitoidentity.AmazonCognitoIdentityClientBuilder
import com.amazonaws.services.cognitoidentity.model._
import com.amazonaws.services.cognitoidp.model._
import com.amazonaws.services.cognitoidp.{AWSCognitoIdentityProvider, AWSCognitoIdentityProviderClientBuilder}
import play.api.libs.json.JsValue

import scala.collection.JavaConverters._
import scala.concurrent.{ExecutionContext, Future}

case class CognitoHelper()(implicit val actorSystem: ActorSystem, val materializer: ActorMaterializer, val executionContext: ExecutionContext) {
  private val POOL_ID = Constants.POOL_ID
  private val CLIENTAPP_ID = Constants.CLIENTAPP_ID
  private val FED_POOL_ID = Constants.FED_POOL_ID
  private val CUSTOMDOMAIN = Constants.CUSTOMDOMAIN
  private val REGION = Constants.REGION

  def getHostedSignInURL(): String = {
    val customUrl = "https://%s.auth.%s.amazoncognito.com/login?response_type=code&client_id=%s&redirect_uri=%s"
    String.format(customUrl, CUSTOMDOMAIN, REGION, CLIENTAPP_ID, Constants.REDIRECT_URL)
  }

  def getTokenURL = {
    val customurl = "https://%s.auth.%s.amazoncognito.com/oauth2/token"
    String.format(customurl, CUSTOMDOMAIN, REGION)
  }

  /**
    * Sign up the user to the user pool
    *
    * @param username    User name for the sign up
    * @param password    Password for the sign up
    * @param email       email used to sign up
    * @param phonenumber phone number to sign up.
    * @return whether the call was successful or not.
    */
  def signUpUser(username: String, password: String, email: String, phonenumber: String): SignUpResult = {
    val awsCreds: AnonymousAWSCredentials = new AnonymousAWSCredentials
    val cognitoIdentityProvider: AWSCognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
      .standard
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .withRegion(Regions.fromName(REGION))
      .build
    val signUpRequest: SignUpRequest = new SignUpRequest
    signUpRequest.setClientId(CLIENTAPP_ID)
    signUpRequest.setUsername(username)
    signUpRequest.setPassword(password)

    val attributeType: AttributeType = new AttributeType
    attributeType.setName("phone_number")
    attributeType.setValue(phonenumber)

    val attributeType1: AttributeType = new AttributeType
    attributeType1.setName("email")
    attributeType1.setValue(email)

    val list: List[AttributeType] = List[AttributeType](attributeType, attributeType1)

    signUpRequest.setUserAttributes(list.asJava)
    cognitoIdentityProvider.signUp(signUpRequest)
  }

  def confirmSignupAccessCode(username: String, code: String): ConfirmSignUpResult = {
    val awsCreds = new AnonymousAWSCredentials
    val cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder.standard.withCredentials(new AWSStaticCredentialsProvider(awsCreds)).withRegion(Regions.fromName(REGION)).build
    val confirmSignUpRequest = new ConfirmSignUpRequest
    confirmSignUpRequest.setUsername(username)
    confirmSignUpRequest.setConfirmationCode(code)
    confirmSignUpRequest.setClientId(CLIENTAPP_ID)

    cognitoIdentityProvider.confirmSignUp(confirmSignUpRequest)
  }

  def validateUser(username: String, password: String): String = {
    val helper = AuthenticationHelper(POOL_ID, CLIENTAPP_ID, "")
    helper.performSRPAuthentication(username, password)
  }

  def getCredentials(idprovider: String, id: String): Credentials = {
    val awsCreds = new AnonymousAWSCredentials
    val provider = AmazonCognitoIdentityClientBuilder.standard
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .withRegion(Regions.fromName(REGION))
      .build
    val idrequest = new GetIdRequest
    idrequest.setIdentityPoolId(FED_POOL_ID)
    idrequest.addLoginsEntry(idprovider, id)

    val idResult = provider.getId(idrequest)
    val request = new GetCredentialsForIdentityRequest
    request.setIdentityId(idResult.getIdentityId)
    request.addLoginsEntry(idprovider, id)
    val result = provider.getCredentialsForIdentity(request)
    result.getCredentials
  }

  def getCredentials(accesscode: String): Future[Credentials] = {
    val httpBodyParams = Map[String, String](
      (Constants.TOKEN_GRANT_TYPE, Constants.TOKEN_GRANT_TYPE_AUTH_CODE),
      (Constants.DOMAIN_QUERY_PARAM_CLIENT_ID, CLIENTAPP_ID),
      (Constants.DOMAIN_QUERY_PARAM_REDIRECT_URI, Constants.REDIRECT_URL),
      (Constants.TOKEN_AUTH_TYPE_CODE, accesscode))

    val httpClient: AuthHttpClient = new AuthHttpClient
    val resultWS = httpClient.httpPost(getTokenURL, httpBodyParams)

    resultWS.map { wsResp ⇒
      val payload: JsValue = CognitoJWTParser.getPayload(wsResp.body)
      val provider = (payload \ "iss").as[String].replace("https://", "")
      getCredentials(provider, wsResp.body)
    }
  }

  def resetPassword(username: String): String = {
    val awsCreds = new AnonymousAWSCredentials()
    val cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
      .standard()
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .withRegion(Regions.fromName(REGION))
      .build()
    val forgotPasswordRequest = new ForgotPasswordRequest()
    forgotPasswordRequest.setUsername(username)
    forgotPasswordRequest.setClientId(CLIENTAPP_ID)
    val forgotPasswordResult = cognitoIdentityProvider.forgotPassword(forgotPasswordRequest)
    forgotPasswordResult.toString
  }

  def updatePassword(username: String, newpw: String, code: String): String = {
    val awsCreds = new AnonymousAWSCredentials()
    val cognitoIdentityProvider = AWSCognitoIdentityProviderClientBuilder
      .standard()
      .withCredentials(new AWSStaticCredentialsProvider(awsCreds))
      .withRegion(Regions.fromName(REGION))
      .build()

    val confirmPasswordRequest = new ConfirmForgotPasswordRequest
    confirmPasswordRequest.setUsername(username)
    confirmPasswordRequest.setPassword(newpw)
    confirmPasswordRequest.setConfirmationCode(code)
    confirmPasswordRequest.setClientId(CLIENTAPP_ID)

    val confirmPasswordResult = cognitoIdentityProvider.confirmForgotPassword(confirmPasswordRequest)
    confirmPasswordResult.toString
  }

}
