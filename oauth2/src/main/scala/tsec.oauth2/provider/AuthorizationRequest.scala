package tsec.oauth2.provider

import cats.implicits._
import java.util.Base64

import scala.collection.immutable.TreeMap
import scala.util.Try

case class ClientCredential(clientId: String, clientSecret: Option[String])

case class AuthorizationRequest(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]) {
  private val orderedHeaders = new TreeMap[String, Seq[String]]()(Ordering.by(_.toLowerCase)) ++ headers

  def scope: Option[String] = params.get(SCOPE).flatMap(_.headOption)

  def grantType(isClientCredRequiredForPasswordGrantType: Boolean): Either[OAuthError, GrantType] =
    for {
      header <- params.get(GRANT_TYPE).flatMap(_.headOption).toRight(InvalidRequest("Missing grant type"))
      res <- GrantType.strToGrantType
        .get(header.toLowerCase)
        .toRight(UnsupportedGrantType(s"unsupported grant type: $header"))
    } yield res

  def parseClientCredential: Either[OAuthError, ClientCredential] = {
    val authHeader = for {
      h <- orderedHeaders
        .get("authorization")
        .flatMap(_.headOption)
        .toRight[OAuthError](InvalidClient("Missing authorization header"))
      matcher <- """^\s*Basic\s+(.+?)\s*$""".r.findFirstMatchIn(h).toRight(InvalidAuthorizationHeader)
      cred = matcher.group(1)
      r <- clientCredentialByAuthorization(cred)
    } yield r
    authHeader.fold[Either[OAuthError, ClientCredential]](
      e => {
        e match {
          case InvalidAuthorizationHeader => InvalidAuthorizationHeader.asLeft[ClientCredential]
          case _ =>
            clientCredentialByParam.toRight(
              InvalidClient(s"Failed to parse client credential from header (${e.description}) and params")
            )
        }
      },
      Right(_)
    )
  }

  private def clientCredentialByAuthorization(s: String): Either[InvalidClient, ClientCredential] =
    Try(new String(Base64.getDecoder.decode(s), "UTF-8"))
      .map(_.split(":", 2))
      .getOrElse(Array.empty) match {
      case Array(clientId, clientSecret) =>
        Right(ClientCredential(clientId, if (clientSecret.isEmpty) None else Some(clientSecret)))
      case _ =>
        Left(InvalidClient("invalid Base 64"))
    }

  private def clientCredentialByParam: Option[ClientCredential] =
    for {
      clientId <- params.get(CLIENT_ID).flatMap(_.headOption)
    } yield ClientCredential(clientId, params.get(CLIENT_SECRET).flatMap(_.headOption))
}
