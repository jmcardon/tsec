package tsec.oauth2.provider

import java.net.URLDecoder

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
  val RegexpDivComma     = """,\s*""".r

  override def matches(request: ProtectedResourceRequest): Boolean =
    request.header("Authorization").exists { header =>
      RegexpAuthorization.findFirstMatchIn(header).isDefined
    }

  override def fetch(request: ProtectedResourceRequest): Either[OAuthError, FetchResult] =
    for {
      header  <- request.header("authorization").toRight(InvalidRequest("Missing authorization header"))
      matcher <- RegexpAuthorization.findFirstMatchIn(header).toRight(InvalidRequest("invalid Authorization header"))
    } yield {
      val token = matcher.group(2)
      val end   = matcher.end
      val params = if (header.length != end) {
        val trimmedHeader = RegexpTrim.replaceFirstIn(header.substring(end), "")
        val pairs = RegexpDivComma.split(trimmedHeader).map { exp =>
          val (key, value) = exp.split("=", 2) match {
            case Array(k, v) => (k, v.replaceFirst("^\"", ""))
            case Array(k)    => (k, "")
          }

          (key, URLDecoder.decode(value.replaceFirst("\"$", ""), "UTF-8"))
        }

        Map(pairs: _*)
      } else {
        Map.empty[String, String]
      }

      FetchResult(token, params)
    }
}
