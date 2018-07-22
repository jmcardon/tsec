package tsec.oauth2.provider

import scala.collection.immutable.TreeMap

final case class ProtectedResourceRequest(headers: Map[String, Seq[String]], params: Map[String, Seq[String]]) {
  private val orderedHeaders = new TreeMap[String, Seq[String]]()(Ordering.by(_.toLowerCase)) ++ headers

  def header(name: String): Option[String] = orderedHeaders.get(name).flatMap { _.headOption }

  def oauthToken: Option[String] = params.get("oauth_token").flatMap(values => values.headOption)

  def accessToken: Option[String] = params.get("access_token").flatMap(values => values.headOption)
}
