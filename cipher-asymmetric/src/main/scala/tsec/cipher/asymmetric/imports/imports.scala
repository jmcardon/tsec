package tsec.cipher.asymmetric

import java.security.{PrivateKey => JPrivateKey, PublicKey => JPublicKey}

import cats.Id
import cats.evidence.Is
import tsec.common.CryptoTag

package object imports {

  protected[tsec] case class AsymmetricAlgorithm[T](algorithm: String, keyLength: Int) extends CryptoTag[T]

  sealed case class KeyPair[A](privateKey: PrivateKey[A], publicKey: PublicKey[A])
  object KeyPair {
    def apply[A](jPrivateKey: JPrivateKey, jPublicKey: JPublicKey): KeyPair[A] =
      new KeyPair[A](PrivateKey[A](jPrivateKey), PublicKey[A](jPublicKey))
  }

  sealed trait TaggedKey[T] {
    type KeyRepr[A] <: Id[T]
    def is[A]: Is[KeyRepr[A], T]
  }

  protected val PublicKey$$ : TaggedKey[JPublicKey] = new TaggedKey[JPublicKey] {
    type KeyRepr[A] = Id[JPublicKey]

    def is[A] = Is.refl[JPublicKey]
  }
  protected val PrivateKey$$ : TaggedKey[JPrivateKey] = new TaggedKey[JPrivateKey] {

    type KeyRepr[A] = Id[JPrivateKey]

    def is[A] = Is.refl[JPrivateKey]
  }

  type PublicKey[A] = PublicKey$$.KeyRepr[A]

  type PrivateKey[A] = PrivateKey$$.KeyRepr[A]

  object PublicKey {
    @inline def apply[A](key: JPublicKey): PublicKey[A] = PublicKey$$.is[A].flip.coerce(key)
  }

  object PrivateKey {
    @inline def apply[A](key: JPrivateKey): PrivateKey[A] = PrivateKey$$.is[A].flip.coerce(key)
  }

}
