package fucc.symmetric.instances

import javax.crypto.spec.SecretKeySpec
import javax.crypto.{KeyGenerator => KG, SecretKey => JSecretKey}

import cats.syntax.either._
import com.softwaremill.tagging._
import fucc.cipher.core.{CipherAlgo, SecretKey}
import fucc.symmetric.core.{KeyError, SymmetricKeyGenerator}

object JSymmetricKeyGenerator {
  def fromType[T](tag: CipherAlgo[T]): SymmetricKeyGenerator[JSymmetric[T]] =
    new SymmetricKeyGenerator[JSymmetric[T]] {
      def generator: KG = KG.getInstance(tag.algorithm)

      def generateKeyUnsafe(): SecretKey[JSymmetric[T]] =
        SecretKey[JSymmetric[T]](generator.generateKey().taggedWith[T])

      def generateKey(): Either[KeyError, SecretKey[JSymmetric[T]]] =
        Either
          .catchNonFatal(
            SecretKey[JSymmetric[T]](generator.generateKey().taggedWith[T]))
          .leftMap(e => KeyError(e.getMessage))

      def buildKeyUnsafe(key: Array[Byte]): SecretKey[JSymmetric[T]] =
        SecretKey(new SecretKeySpec(key, tag.algorithm).taggedWith[T])

      def buildKey(key: Array[Byte]): Either[KeyError, SecretKey[JSecretKey @@ T]] =
        Either.catchNonFatal(SecretKey[JSymmetric[T]](new SecretKeySpec(key, tag.algorithm).taggedWith[T]))
          .leftMap(e => KeyError(e.getMessage))
    }
}