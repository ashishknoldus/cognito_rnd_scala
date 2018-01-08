package controllers

import javax.inject.Inject

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import cognito.CognitoHelper
import play.api.mvc.{AbstractController, ControllerComponents}

import scala.concurrent.ExecutionContext

class SigninController  @Inject()(cc: ControllerComponents, system: ActorSystem) extends AbstractController(cc) {

  def signin() = Action { request ⇒
    val form: Option[Map[String, Seq[String]]] = request.body.asFormUrlEncoded

    implicit val actorSystem: ActorSystem = system
    implicit val materializer: ActorMaterializer = ActorMaterializer()(system)
    implicit val ec: ExecutionContext = cc.executionContext

    val cognitoHelper = CognitoHelper()

    form match {
      case Some(map) ⇒ val siginResult = cognitoHelper.validateUser(map("username").head, map("password").head)
        Ok("SiginResult -- " + siginResult.toString)
      case None ⇒ BadRequest("Fill the signin form")
    }
  }
}
