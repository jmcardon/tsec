package tsec.jwt.header

trait JWTHeader {
  def `type`: Option[String]
  def contentType: Option[String] // Not Recommended
}