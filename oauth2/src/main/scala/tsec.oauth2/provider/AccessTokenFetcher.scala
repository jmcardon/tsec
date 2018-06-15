package tsec.oauth2.provider

import cats.implicits._
import java.net.URLDecoder

import cats.data.NonEmptyList

final case class FetchResult(token: String, params: Map[String, String])

trait AccessTokenFetcher {
  def matches(request: ProtectedResourceRequest): Boolean
  def fetch(request: ProtectedResourceRequest): Either[OAuthError, FetchResult]
}

object RequestParameter extends AccessTokenFetcher {

  override def matches(request: ProtectedResourceRequest): Boolean =
    request.oauthToken.isDefined || request.accessToken.isDefined

  override def fetch(request: ProtectedResourceRequest): Either[OAuthError, FetchResult] = {
    val t      = request.oauthToken orElse (request.accessToken)
    val params = request.params.filter { case (_, v) => !v.isEmpty } map { case (k, v) => (k, v.head) }
    t.map(s => FetchResult(s, params - ("oauth_token", "access_token"))).toRight(InvalidRequest("missing access token"))
  }
}

object AuthHeader extends AccessTokenFetcher {
  val RegexpAuthorization = """^\s*(OAuth|Bearer)\s+([^\s\,]*)""".r
  val RegexpTrim          = """^\s*,\s*""".r
  val RegexpDivComma      = """,\s*""".r

  override def matches(request: ProtectedResourceRequest): Boolean =
    request.header("Authorization").exists { header =>
      RegexpAuthorization.findFirstMatchIn(header).isDefined
    }

  override def fetch(request: ProtectedResourceRequest): Either[InvalidRequest, FetchResult] =
    for {
      header  <- request.header("authorization").toRight(InvalidRequest("Missing authorization header"))
      matcher <- RegexpAuthorization.findFirstMatchIn(header).toRight(InvalidRequest("invalid Authorization header"))
      token = matcher.group(2)
      end   = matcher.end
      params <- if (header.length != end) {
        val trimmedHeader = RegexpTrim.replaceFirstIn(header.substring(end), "")
        val pairs = RegexpDivComma.split(trimmedHeader).map { exp =>
          val (key, value) = exp.split("=", 2) match {
            case Array(k, v) => (k, v.replaceFirst("^\"", ""))
            case Array(k)    => (k, "")
          }

          val v = Either.catchNonFatal(URLDecoder.decode(value.replaceFirst("\"$", ""), "UTF-8"))
          v.map(vv => (key, vv)).leftMap(t => NonEmptyList.one(t.getMessage))
        }

        pairs.toList.parSequence.map(x => Map(x: _*)).leftMap(x => InvalidRequest(x.toList.mkString(",")))
      } else {
        Right(Map.empty[String, String])
      }

    } yield FetchResult(token, params)
}
