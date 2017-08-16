package tsec.mac.instance

import javax.crypto.Mac

import cats.syntax.either._
import tsec.cipher.common.{CipherError, InstanceInitError, KeyError, SignError}
import tsec.mac.MacKey
import tsec.mac.core.{MacAlgebra, MacSigningKey}


class JMacInterpreter[A](implicit macTag: MacTag[A]) extends MacAlgebra[Either[CipherError, ?], A, MacKey] {
  type M = Mac

  def genInstance: Either[CipherError, Mac] =
    Either
      .catchNonFatal(Mac.getInstance(macTag.algorithm))
      .leftMap(InstanceInitError.fromThrowable)

  def sign(content: Array[Byte], key: MacSigningKey[MacKey[A]]): Either[CipherError, Array[Byte]] =
    for {
      instance <- genInstance
      _        <- Either.catchNonFatal(instance.init(key.key)).leftMap(KeyError.fromThrowable)
      fin      <- Either.catchNonFatal(instance.doFinal(content)).leftMap(SignError.fromThrowable)
    } yield fin
}
