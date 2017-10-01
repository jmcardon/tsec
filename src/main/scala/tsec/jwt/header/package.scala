package tsec.jwt
import io.circe._

package object header {

  type JWTtyp = JWTtyp.type

  case object JWTtyp {

    val repr: String = "JWT"

    implicit val encoder: Encoder[JWTtyp] = new Encoder[JWTtyp] {
      def apply(a: JWTtyp): Json = Json.fromString(repr)
    }

    implicit val decoder: Decoder[JWTtyp] = new Decoder[JWTtyp] {
      def apply(c: HCursor): Decoder.Result[JWTtyp] = c.as[String].flatMap {
        case JWTtyp.repr => Right(JWTtyp)
        case _           => Left(DecodingFailure("invalid mime type for jwt", Nil))
      }
    }

  }
}
