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
class JMacInterpreter[A](implicit macTag: MacTag[A]) extends MacAlgebra[Either[Throwable,?],A, MacKey]  {
  type M = Mac

  def genInstance: Either[Throwable, Mac] = Either.catchNonFatal(Mac.getInstance(macTag.algorithm))

  def sign(content: Array[Byte], key: MacSigningKey[MacKey[A]]): Either[Throwable,Array[Byte]] = {
    for {
      instance <- genInstance
      _ <- Either.catchNonFatal(instance.init(key.key))
      fin <- Either.catchNonFatal(instance.doFinal(content))
    } yield fin
  }
}
