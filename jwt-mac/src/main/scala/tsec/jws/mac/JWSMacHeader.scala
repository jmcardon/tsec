package tsec.jws.mac

import tsec.common._
import cats.data.NonEmptyList
import io.circe._
import io.circe.syntax._
import tsec.jws.JWSSerializer
import tsec.jwt.algorithms.JWTMacAlgo
import tsec.jws.header.JWSHeader
import tsec.jwt
import tsec.jwt.header.JWTtyp
import tsec.mac.imports.MacTag

/** A JWS header for JWT serialization.
  * TODO: Crit logic on verification
  *
  * @param `type` the type of the content. in a less opininated library, it could signal json serialization
  * @param contentType The contentType, a non-recommended header
  * @param critical The fields that _must_ be present
  * @tparam A
  */
sealed abstract case class JWSMacHeader[A](
    `type`: Option[JWTtyp] = Some(JWTtyp), //Type, which will almost always default to "JWT"
    contentType: Option[String] = None, // Optional header, preferably not used
    critical: Option[NonEmptyList[String]] = None //Headers not to ignore, they must be understood by the JWT implementation
)(implicit val algorithm: JWTMacAlgo[A])
    extends JWSHeader[A] {
  def toJsonString: String = jwt.JWTPrinter.pretty(this.asJson)
}

object JWSMacHeader {

  def apply[A](implicit algo: JWTMacAlgo[A]): JWSMacHeader[A] =
    new JWSMacHeader[A]() {}

  implicit def encoder[A: JWTMacAlgo]: Encoder[JWSMacHeader[A]] {
    def apply(a: JWSMacHeader[A]): Json
  } = new Encoder[JWSMacHeader[A]] {
    def apply(a: JWSMacHeader[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson)
    )
  }

  /** For our decoder, we we know, a priori, the type of header we should have
    * since we decode for some algorithm A, we avoid the vulnerability of
    * parsing the algorithm, then verifying against it.
    * That is, the server should know the algorithm before trying to deserialize it.
    *
    * @tparam A
    * @return
    */
  implicit def decoder[A: MacTag: JWTMacAlgo]: Decoder[JWSMacHeader[A]] = new Decoder[JWSMacHeader[A]] {
    def apply(c: HCursor): Either[DecodingFailure, JWSMacHeader[A]] =
      c.downField("alg")
        .as[String]
        .map(JWTMacAlgo.fromString[A]) match {
        case Right(opt) =>
          opt match {
            case Some(_) =>
              for {
                t     <- c.downField("typ").as[Option[JWTtyp]]
                cType <- c.downField("cty").as[Option[String]]
                crit  <- c.downField("crit").as[Option[NonEmptyList[String]]]
              } yield
                new JWSMacHeader[A](
                  `type` = t,
                  contentType = cType,
                  critical = crit
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }

        case Left(d) => Left(d)
      }
  }

  implicit def genSerializer[A: JWTMacAlgo](
      implicit d: Decoder[JWSMacHeader[A]],
      e: Encoder[JWSMacHeader[A]]
  ): JWSSerializer[JWSMacHeader[A]] =
    new JWSSerializer[JWSMacHeader[A]] {
      def serializeToUtf8(body: JWSMacHeader[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes

      def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSMacHeader[A]] =
        io.circe.parser.decode[JWSMacHeader[A]](array.toUtf8String)
    }
}
