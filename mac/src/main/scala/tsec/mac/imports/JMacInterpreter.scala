package tsec.mac.imports

import javax.crypto.Mac

import cats.syntax.either._
import tsec.core.ErrorConstruct
import tsec.mac.core.MacAlgebra

/**
  * Our interpreter over the JCA mac
  *
  * @param macTag
  * @tparam A
  */
class JMacInterpreter[A](implicit macTag: MacTag[A]) extends MacAlgebra[MacErrorM, A, MacSigningKey] {
  type M = Mac

  def genInstance: Either[MacInstanceError, Mac] =
    Either
      .catchNonFatal(Mac.getInstance(macTag.algorithm))
      .leftMap(ErrorConstruct.fromThrowable[MacInstanceError])

  def sign(content: Array[Byte], key: MacSigningKey[A]): Either[MacError, Array[Byte]] =
    for {
      instance <- genInstance
      _        <- Either.catchNonFatal(instance.init(key.key)).leftMap(ErrorConstruct.fromThrowable[MacInitError])
      fin      <- Either.catchNonFatal(instance.doFinal(content)).leftMap(ErrorConstruct.fromThrowable[MacSigningError])
    } yield fin
}
