package tsec.mac.imports

import javax.crypto.Mac

import cats.syntax.either._
import tsec.common.ErrorConstruct._
import tsec.mac.core.{MacAlgebra, MacTag}

/** JCA mac interpreter
  *
  * @param macTag
  * @tparam A
  */
class JMacInterpreter[A](implicit macTag: MacTag[A]) extends MacAlgebra[MacErrorM, A, MacSigningKey] {
  type M = Mac

  def genInstance: Either[MacInstanceError, Mac] =
    Either
      .catchNonFatal(Mac.getInstance(macTag.algorithm))
      .mapError(MacInstanceError.apply)

  def sign(content: Array[Byte], key: MacSigningKey[A]): Either[MacError, Array[Byte]] =
    for {
      instance <- genInstance
      _        <- Either.catchNonFatal(instance.init(MacSigningKey.toJavaKey[A](key))).mapError(MacInitError.apply)
      fin      <- Either.catchNonFatal(instance.doFinal(content)).mapError(MacSigningError.apply)
    } yield fin
}
