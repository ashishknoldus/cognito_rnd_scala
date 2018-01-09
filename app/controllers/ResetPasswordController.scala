package controllers

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import cognito.CognitoHelper
import com.google.inject.Inject
import play.api.mvc.{AbstractController, ControllerComponents}

import scala.concurrent.ExecutionContext

class ResetPasswordController @Inject()(ss: ControllerComponents, system: ActorSystem) extends AbstractController(ss){

  def resetPassword = Action { request ⇒
    val form = request.body.asFormUrlEncoded

    implicit val actorSystem: ActorSystem = system
    implicit val materializer: ActorMaterializer = ActorMaterializer()(system)
    implicit val ec: ExecutionContext = ss.executionContext

    val cognitoHelper = CognitoHelper()

    form match {
      case Some(map) ⇒ val resetPasswordResult = cognitoHelper.resetPassword(map("username").head)
        Ok(s"resetPasswordResult - ${resetPasswordResult}")
      case None ⇒
        BadRequest("Wrong credentitals entered in the form")
    }
  }

}
