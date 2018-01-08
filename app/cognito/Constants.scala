package cognito

import com.typesafe.config.ConfigFactory

object Constants {

  println("\n\n\n\n\nLoading the constants :)\n\n\n\n\n")
  print(s"\n\n\n\n\nREGION -- ")
  println(s"${ConfigFactory.load().getString("cognito.region")}:)\n\n\n\n\n")

  val DOMAIN_QUERY_PARAM_CLIENT_ID = "client_id"

  val DOMAIN_QUERY_PARAM_REDIRECT_URI = "redirect_uri"
  val TOKEN_AUTH_TYPE_CODE = "code"
  val TOKEN_GRANT_TYPE = "READ"
  val TOKEN_GRANT_TYPE_AUTH_CODE = "authorization_code"

  val HTTP_HEADER_PROP_CONTENT_TYPE = "Content-Type"
  val HTTP_HEADER_PROP_CONTENT_TYPE_DEFAULT = "application/x-www-form-urlencoded"
  val HTTP_REQUEST_TYPE_POST = "POST"
  val REDIRECT_URL = "https://sid343.reinvent-workshop.com"
  val HTTP_REQUEST_TIMEOUT = 3000

  val config = ConfigFactory.load()
  val REGION = config.getString("cognito.region")
  print("The region is -- "); println(REGION)
  val POOL_ID = config.getString("cognito.pool_id")
  val CLIENTAPP_ID = config.getString("cognito.clientapp_id")
  val FED_POOL_ID = config.getString("cognito.fed_pool_id")
  val CUSTOMDOMAIN = config.getString("cognito.customdomain")
}
