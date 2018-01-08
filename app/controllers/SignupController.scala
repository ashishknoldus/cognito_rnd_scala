package controllers

import javax.inject.Inject

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import cognito.CognitoHelper
import play.api.mvc.{AbstractController, ControllerComponents}

import scala.concurrent.ExecutionContext

class SignupController @Inject()(cc: ControllerComponents, system: ActorSystem) extends AbstractController(cc) {

  def signup() = Action { request ⇒
    val form: Option[Map[String, Seq[String]]] = request.body.asFormUrlEncoded

    implicit val actorSystem: ActorSystem = system
    implicit val materializer: ActorMaterializer = ActorMaterializer()(system)
    implicit val ec: ExecutionContext = cc.executionContext

    val cognitoHelper = CognitoHelper()

    form match {
      case Some(map) ⇒ val signupResult = cognitoHelper.signUpUser(map("username").head, map("password").head,
        map("email").head, map("phonenumber").head)
        val signUpResultString = signupResult.toString
        Ok("\n\nSignup result is --- " + signUpResultString)
      case None ⇒
        BadRequest("Wrong credentitals entered in the form")
    }
  }

}
