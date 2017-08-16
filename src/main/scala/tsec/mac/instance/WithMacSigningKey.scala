package tsec.mac.instance

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.syntax.either._
import shapeless.Generic
import tsec.core.{JKeyGenerator, KeyBuilderError}
import tsec.mac.core.MacSigningKey
import tsec.mac.{MacKey, tagKey}

abstract class WithMacSigningKey[A](algorithm: String, keyLen: Int) {

  implicit val gen: Generic[A] = Generic[A]
  implicit val macTag: MacTag[A] = MacTag[A](algorithm, keyLen)
  implicit val keyGen = new JKeyGenerator[MacKey[A], MacSigningKey] {

    def generator: KeyGenerator = KeyGenerator.getInstance(algorithm)

    def keyLength: Int = keyLen

    def generateKey(): Either[KeyBuilderError, MacSigningKey[MacKey[A]]] =
      Either.catchNonFatal(MacSigningKey(tagKey[A](generator.generateKey()))).leftMap(KeyBuilderError.fromThrowable)

    def generateKeyUnsafe(): MacSigningKey[MacKey[A]] = MacSigningKey(tagKey[A](generator.generateKey()))

    def buildKey(key: Array[Byte]): Either[KeyBuilderError, MacSigningKey[MacKey[A]]] =
      Either
        .catchNonFatal(MacSigningKey(tagKey[A](new SecretKeySpec(key.slice(0, keyLen), algorithm))))
        .leftMap(KeyBuilderError.fromThrowable)

    def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[MacKey[A]] =
      MacSigningKey(tagKey[A](new SecretKeySpec(key.slice(0, keyLen), algorithm)))
  }

}
