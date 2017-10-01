package tsec.jwt.header

trait JWTHeader {
  def `type`: Option[JWTtyp]
  def contentType: Option[String] // Not Recommended
}
