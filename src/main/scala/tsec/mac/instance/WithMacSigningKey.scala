package tsec.mac.instance

import javax.crypto.KeyGenerator
import javax.crypto.spec.SecretKeySpec

import cats.syntax.either._
import tsec.cipher.common.KeyError
import tsec.core.JKeyGenerator
import tsec.mac.core.MacSigningKey
import tsec.mac.{MacKey, tagKey}

abstract class WithMacSigningKey[A](algorithm: String, keyLen: Int) {

  implicit val macTag: MacTag[A] = MacTag[A](algorithm, keyLen)
  implicit val keyGen = new JKeyGenerator[MacKey[A], MacSigningKey] {

    def generator: KeyGenerator = KeyGenerator.getInstance(algorithm)

    def keyLength: Int = keyLen

    def generateKey(): Either[KeyError, MacSigningKey[MacKey[A]]] =
      Either.catchNonFatal(MacSigningKey(tagKey[A](generator.generateKey()))).leftMap(KeyError.fromThrowable)

    def generateKeyUnsafe(): MacSigningKey[MacKey[A]] = MacSigningKey(tagKey[A](generator.generateKey()))

    def buildKey(key: Array[Byte]): Either[KeyError, MacSigningKey[MacKey[A]]] =
      Either
        .catchNonFatal(MacSigningKey(tagKey[A](new SecretKeySpec(key.slice(0, keyLen), algorithm))))
        .leftMap(KeyError.fromThrowable)

    def buildKeyUnsafe(key: Array[Byte]): MacSigningKey[MacKey[A]] =
      MacSigningKey(tagKey[A](new SecretKeySpec(key.slice(0, keyLen), algorithm)))
  }

}
