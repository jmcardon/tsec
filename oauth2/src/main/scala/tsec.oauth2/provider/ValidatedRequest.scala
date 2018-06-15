package tsec.oauth2.provider

import java.nio.charset.StandardCharsets

import cats.implicits._
import tsec.common._
import tsec.oauth2.provider.GrantType.ClientCrendentials
import tsec.oauth2.provider.GrantType.Password

import scala.collection.immutable.TreeMap
import scala.util.Try

case class ClientCredential(clientId: String, clientSecret: Option[String])



sealed abstract class ValidatedRequest extends Product with Serializable{
  def scope: Option[String]
  def grantType: GrantType
}
object ValidatedRequest{
  def create(grantType: GrantType, isClientCredRequiredForPasswordGrantType: Boolean, headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedRequest] = grantType match {
    case GrantType.AuthorizationCode =>
      ValidatedAuthorizationCode.create(headers, params)
    case GrantType.RefreshToken =>
      ValidatedRefreshToken.create(headers, params)
    case ClientCrendentials =>
      ValidatedClientCrendentials.create(headers, params)
    case Password =>
      if (isClientCredRequiredForPasswordGrantType)
        ValidatedPasswordWithClientCred.create(headers, params)
      else
        ValidatedPasswordNoClientCred.create(params)
    case GrantType.Implicit =>
      ValidatedImplicit.create(headers, params)
  }

  case class ValidatedAuthorizationCode(clientCredential: ClientCredential, code: String, scope: Option[String], redirectUri: Option[String]) extends ValidatedRequest {
    def grantType: GrantType = GrantType.AuthorizationCode
  }

  def getScope(params: Map[String, Seq[String]]): Option[String] = params.get(Scope).flatMap(_.headOption)

  object ValidatedAuthorizationCode{
    def create[F[_]](headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedAuthorizationCode] = for{
      credential <- parseClientCredential(headers, params)
      code <- params.get("code").flatMap(_.headOption).toRight(InvalidRequest("missing code param"))
    }yield ValidatedAuthorizationCode(credential, code, getScope(params), params.get("redirect_uri").flatMap(_.headOption))
  }

  object ValidatedRefreshToken{
    def create[F[_]](headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedRefreshToken] = for{
      credential <- parseClientCredential(headers, params)
      res <- params
        .get("refresh_token")
        .flatMap(_.headOption)
        .toRight(InvalidRequest("missing refresh_token param"))
    }yield new ValidatedRefreshToken(credential, res, getScope(params))
  }

  case class ValidatedRefreshToken(clientCredential: ClientCredential, refreshToken: String, scope: Option[String]) extends ValidatedRequest {
    def name: String = "refresh_token"
    def grantType: GrantType = GrantType.RefreshToken
  }

  case class ValidatedClientCrendentials(clientCredential: ClientCredential, scope: Option[String]) extends ValidatedRequest {
    def grantType: GrantType = GrantType.ClientCrendentials
  }

  object ValidatedClientCrendentials{
    def create(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedClientCrendentials] = for{
      credential <- parseClientCredential(headers, params)
    }yield ValidatedClientCrendentials(credential, getScope(params))
  }

  case class ValidatedPasswordWithClientCred(clientCredential: ClientCredential, password: String, username: String, scope: Option[String]) extends ValidatedRequest {
    def grantType: GrantType = GrantType.Password
  }

  object ValidatedPasswordWithClientCred{
    def create(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedPasswordWithClientCred] = for{
      credential <- parseClientCredential(headers, params)
      password <-
        params.get("password").flatMap(_.headOption).toRight(InvalidRequest("missing password param"))
      username <-
        params.get("username").flatMap(_.headOption).toRight(InvalidRequest("missing username param"))
    }yield ValidatedPasswordWithClientCred(credential, password, username, getScope(params))
  }

  case class ValidatedPasswordNoClientCred(password: String, username: String, scope: Option[String]) extends ValidatedRequest {
    def grantType: GrantType = GrantType.Password
  }

  object ValidatedPasswordNoClientCred{
    def create(params: Map[String, Seq[String]]): Either[InvalidRequest, ValidatedPasswordNoClientCred] = for{
      password <-
        params.get("password").flatMap(_.headOption).toRight(InvalidRequest("missing password param"))
      username <-
        params.get("username").flatMap(_.headOption).toRight(InvalidRequest("missing username param"))
    }yield ValidatedPasswordNoClientCred(password, username, getScope(params))
  }

  case class ValidatedImplicit(clientCredential: ClientCredential, scope: Option[String]) extends ValidatedRequest {
    def name: String = "implicit"
    def grantType: GrantType = GrantType.Implicit
  }


  object ValidatedImplicit{
    def create(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ValidatedImplicit] = for{
      credential <- parseClientCredential(headers, params)
    }yield ValidatedImplicit(credential, getScope(params))
  }

  private def parseClientCredential(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]): Either[OAuthError, ClientCredential] = {
    val orderedHeaders = new TreeMap[String, Seq[String]]()(Ordering.by(_.toLowerCase)) ++ headers
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
            clientCredentialByParam(params).toRight(
              InvalidClient(s"Failed to parse client credential from header (${e.description}) and params")
            )
        }
      },
      Right(_)
    )
  }

  private def clientCredentialByAuthorization(s: String): Either[InvalidClient, ClientCredential] =
    Try(new String(s.base64Bytes, StandardCharsets.UTF_8))
      .map(_.split(":", 2))
      .getOrElse(Array.empty) match {
      case Array(clientId, clientSecret) =>
        Right(ClientCredential(clientId, if (clientSecret.isEmpty) None else Some(clientSecret)))
      case _ =>
        Left(InvalidClient("invalid Base 64"))
    }

  private def clientCredentialByParam(params: Map[String, Seq[String]]): Option[ClientCredential] =
    for {
      clientId <- params.get(ClientId).flatMap(_.headOption)
    } yield ClientCredential(clientId, params.get(ClientSecret).flatMap(_.headOption))
}
