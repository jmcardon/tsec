package tsec.core

import javax.crypto.KeyGenerator

import cats.{ApplicativeError, Monad}
import cats.implicits._

/**
  * Our symmetric key generator, abstracted out
  * This is not so easy given keyError is useful to CipherError as well, but
  * duplicated classes is a nono
  *
  * @tparam A The algorithm to generate the key for
  * @tparam K the key type, i.e Symmetric cipher or Mac key
  */
trait JKeyGenerator[A, K[_], KE] {
  def keyLength: Int
  def generator: KeyGenerator
  def generateKey(): Either[KE, K[A]]
  def generateLift[F[_]](implicit err: ApplicativeError[F, Throwable], ev: KE <:< Throwable): F[K[A]] =
    generateKey() match {
      case Left(e)  => err.raiseError(e)
      case Right(k) => err.pure(k)
    }

  def generateKeyUnsafe(): K[A]
  def buildKey(key: Array[Byte]): Either[KE, K[A]]
  def buildKeyUnsafe(key: Array[Byte]): K[A]
}
