package tsec.mac.jca

import java.security.MessageDigest

import cats.Monad
import javax.crypto.{Mac, SecretKey}
import tsec.mac.{MAC, MessageAuth}
import cats.syntax.functor._
import cats.syntax.flatMap._

abstract class JCAMessageAuth[F[_], A](implicit F: Monad[F])
  extends MessageAuth[F, A, MacSigningKey] {

  protected[tsec] def genInstance: F[Mac]

  protected[tsec] def signInternal(m: Mac, k: SecretKey, content: Array[Byte]): F[MAC[A]]

  def sign(content: Array[Byte], key: MacSigningKey[A]): F[MAC[A]] =
    for {
      instance <- genInstance
      fin      <- signInternal(instance, MacSigningKey.toJavaKey[A](key), content)
    } yield fin

  def verifyBool(toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A]): F[Boolean] =
    F.map(sign(toSign, key))(MessageDigest.isEqual(signed, _))

}