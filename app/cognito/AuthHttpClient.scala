package cognito

import java.net.URLEncoder

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import play.api.libs.ws.{WSClient, WSResponse}
import play.api.libs.ws.ahc.AhcWSClient

import scala.concurrent.Future
import scala.concurrent.duration.DurationInt

final class AuthHttpClient()(implicit val actorSystem: ActorSystem, implicit val materializer: ActorMaterializer) {

   def wsClient: WSClient = AhcWSClient()

  @throws[Exception]
  def httpPost(uri: String, bodyParams: Map[String, String]): Future[WSResponse] = {
    if (bodyParams.size < 1) {
      throw new IllegalArgumentException("Invalid HTTP request parameters")
    }

    val queryString: String = bodyParams
      .map(keyValPair ⇒ URLEncoder.encode(keyValPair._1, "UTF-8") + "=" + URLEncoder.encode(keyValPair._2, "UTF-8"))
      .toList.mkString("&")

    wsClient.url(uri)
      .withHttpHeaders(Constants.HTTP_HEADER_PROP_CONTENT_TYPE -> Constants.HTTP_HEADER_PROP_CONTENT_TYPE_DEFAULT)
      .withRequestTimeout(Constants.HTTP_REQUEST_TIMEOUT.seconds)
      .post(queryString)

  }

}
