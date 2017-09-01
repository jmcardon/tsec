package tsec.jws.header

import cats.data.NonEmptyList
import io.circe._
import io.circe.syntax._
import tsec.jwt
import tsec.jws._
import tsec.jws.algorithms._
import tsec.jwt.header._
import tsec.mac.instance._
import tsec.signature.core.SigAlgoTag
import tsec.core.ByteUtils._
import tsec.messagedigests.instances.{SHA1, SHA256}

sealed trait JWSHeader[A] extends JWTHeader {
  def algorithm: JWA[A]
}

/**
  * A JWS header for JWT serialization.
  *
  *
  * @param `type` the type of the content. in a less opininated library, it could signal json serialization
  * @param algorithm the specified json web algorithm
  * @param contentType The contentType, a non-recommended header
  * @param critical The fields that _must_ be present
  * @tparam A
  */
sealed abstract case class JWSMacHeader[A: MacTag](
                                                    `type`: Option[JWTtyp] = Some(JWTtyp), //Type, which will almost always default to "JWT"
                                                    algorithm: JWTMacAlgo[A], //Algorithm, in this case a MAC
                                                    contentType: Option[String] = None, // Optional header, preferably not used
                                                    critical: Option[NonEmptyList[String]] = None //Headers not to ignore, they must be understood by the JWT implementation
) extends JWSHeader[A]

object JWSMacHeader {

  def apply[A: MacTag](implicit jwtMacAlgo: JWTMacAlgo[A]) =
    new JWSMacHeader[A](
      algorithm = jwtMacAlgo
    ) {}


  implicit def encoder[A: MacTag]: Encoder[JWSMacHeader[A]] {
    def apply(a: JWSMacHeader[A]): Json
  } = new Encoder[JWSMacHeader[A]] {
    def apply(a: JWSMacHeader[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson)
    )
  }

  /**
    * For our decoder, we we know, a priori, the type of header we should have
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
        .as[Option[String]]
        .map(f => JWTMacAlgo.fromString[A](f.getOrElse(""))) match {
        case Right(opt) =>
          opt match {
            case Some(o) =>
              for {
                t     <- c.downField("typ").as[Option[JWTtyp]]
                cType <- c.downField("cty").as[Option[String]]
                crit  <- c.downField("crit").as[Option[NonEmptyList[String]]]
              } yield
                new JWSMacHeader[A](
                  `type` = t,
                  algorithm = o,
                  contentType = cType,
                  critical = crit
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }

        case Left(d) => Left(d)
      }
  }

  implicit def genSerializer[A: MacTag](implicit d: Decoder[JWSMacHeader[A]],
                                        e: Encoder[JWSMacHeader[A]]): JWSSerializer[JWSMacHeader[A]] =
    new JWSSerializer[JWSMacHeader[A]] {
      def serializeToUtf8(body: JWSMacHeader[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes

      def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSMacHeader[A]] =
        io.circe.parser.decode[JWSMacHeader[A]](array.toUtf8String)
    }
}

sealed abstract case class JWSSignedHeader[A: SigAlgoTag](
                                                           `type`: Option[JWTtyp] = Some(JWTtyp), //Type, which will almost always default to "JWT"
                                                           algorithm: JWTSigAlgo[A], //Algorithm, in this case a MAC
                                                           contentType: Option[String] = None, // Optional header, preferably not used
                                                           critical: Option[NonEmptyList[String]] = None, //Headers not to ignore, they must be understood by the JWT implementation
                                                           jku: Option[String] = None, //Resource set for JWK
                                                           jwk: Option[String] = None, //JWK, eventually not a string,
                                                           kid: Option[String] = None, //JWK key hint
                                                           x5u: Option[String] = None, //The "x5c" (X.509 certificate chain) Header Parameter
                                                           x5t: Option[SHA1] = None, //sha1 hash
                                                           `x5t#S256`: Option[SHA256] = None //sha256 hash
) extends JWSHeader[A]

object JWSSignedHeader {
  implicit def encoder[A: SigAlgoTag] = new Encoder[JWSSignedHeader[A]] {
    def apply(a: JWSSignedHeader[A]): Json = Json.obj(
      ("typ", a.`type`.asJson),
      ("alg", a.algorithm.jwtRepr.asJson),
      ("cty", a.contentType.asJson),
      ("crit", a.critical.asJson),
      ("jku", a.jku.asJson),
      ("jwk", a.jwk.asJson),
      ("kid", a.kid.asJson),
      ("x5u", a.x5u.asJson),
      ("x5t", a.x5t.map(_.toBase64String).asJson),
      ("x5t#s256", a.`x5t#S256`.map(_.toBase64String).asJson)
    )
  }

  implicit def decoder[A: SigAlgoTag: JWTSigAlgo]: Decoder[JWSSignedHeader[A]] = new Decoder[JWSSignedHeader[A]] {
    def apply(c: HCursor): Either[DecodingFailure, JWSSignedHeader[A]] =
      c.downField("alg")
        .as[Option[String]]
        .map(f => JWTSigAlgo.fromString[A](f.getOrElse(""))) match {
        case Right(opt) =>
          opt match {
            case Some(o) =>
              for {
                t      <- c.downField("typ").as[Option[JWTtyp]]
                cType  <- c.downField("cty").as[Option[String]]
                crit   <- c.downField("crit").as[Option[NonEmptyList[String]]]
                jku    <- c.downField("jku").as[Option[String]]
                jwk    <- c.downField("jwk").as[Option[String]]
                kid    <- c.downField("kid").as[Option[String]]
                x5u    <- c.downField("x5u").as[Option[String]]
                x5t    <- c.downField("x5t").as[Option[String]]
                x5t256 <- c.downField("x5t#s256").as[Option[String]]
              } yield
                new JWSSignedHeader[A](
                  `type` = t,
                  algorithm = o,
                  contentType = cType,
                  critical = crit,
                  jku = jku,
                  jwk = jwk,
                  kid = kid,
                  x5u = x5u,
                  x5t = x5t.map(h => SHA1(h.base64Bytes)),
                  `x5t#S256` = x5t256.map(h => SHA256(h.base64Bytes))
                ) {}
            case None =>
              Left(DecodingFailure("No algorithm found", Nil))
          }
        case Left(d) => Left(d)
      }
  }

  def genDeserializer[A: SigAlgoTag](
                                      implicit encoder: Encoder[JWSSignedHeader[A]],
                                      decoder: Decoder[JWSSignedHeader[A]]
  ): JWSSerializer[JWSSignedHeader[A]] = new JWSSerializer[JWSSignedHeader[A]] {
    def fromUtf8Bytes(array: Array[Byte]): Either[Error, JWSSignedHeader[A]] =
      io.circe.parser.decode[JWSSignedHeader[A]](array.toUtf8String)

    def serializeToUtf8(body: JWSSignedHeader[A]): Array[Byte] = jwt.JWTPrinter.pretty(body.asJson).utf8Bytes
  }

}
