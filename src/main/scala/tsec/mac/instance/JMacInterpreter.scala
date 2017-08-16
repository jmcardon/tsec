package tsec.mac.instance

import javax.crypto.Mac

import cats.syntax.either._
import tsec.mac.MacKey
import tsec.mac.core.{MacAlgebra, MacSigningKey}

/**
  * TODO: Improve error types
  *
  * @param macTag
  * @tparam A
  */
class JMacInterpreter[A](implicit macTag: MacTag[A]) extends MacAlgebra[Either[MacError, ?], A, MacKey] {
  type M = Mac

  def genInstance: Either[MacInstanceError, Mac] =
    Either
      .catchNonFatal(Mac.getInstance(macTag.algorithm))
      .leftMap(MacInstanceError.fromThrowable)

  def sign(content: Array[Byte], key: MacSigningKey[MacKey[A]]): Either[MacError, Array[Byte]] =
    for {
      instance <- genInstance
      _        <- Either.catchNonFatal(instance.init(key.key)).leftMap(MacInitError.fromThrowable)
      fin      <- Either.catchNonFatal(instance.doFinal(content)).leftMap(MacSigningError.fromThrowable)
    } yield fin
}
