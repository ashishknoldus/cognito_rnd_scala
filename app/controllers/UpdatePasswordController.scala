package controllers

import akka.actor.ActorSystem
import akka.stream.ActorMaterializer
import cognito.CognitoHelper
import com.google.inject.Inject
import play.api.mvc.{AbstractController, ControllerComponents}

import scala.concurrent.ExecutionContext

class UpdatePasswordController @Inject()(cc: ControllerComponents, system: ActorSystem) extends AbstractController(cc) {

  def updatePasswd = Action { request ⇒
    val form = request.body.asFormUrlEncoded

    implicit val actorSystem: ActorSystem = system
    implicit val materializer: ActorMaterializer = ActorMaterializer()(system)
    implicit val ec: ExecutionContext = cc.executionContext

    val cognitoHelper = CognitoHelper()

    form match {
      case Some(map) ⇒ val updatePasswordResult = cognitoHelper.updatePassword(map("username").head, map("newpass").head, map("code").head)
        Ok(s"updatePasswordResult - ${updatePasswordResult}")
      case None ⇒
        BadRequest("Wrong credentitals entered in the form")
    }
  }

}
