package tsec.cipher.asymmetric

import java.security.{PrivateKey => JPrivateKey, PublicKey => JPublicKey}

import cats.evidence.Is
import tsec.common.CryptoTag

package object imports {

  protected[tsec] case class AsymmetricAlgorithm[T](algorithm: String, keyLength: Int) extends CryptoTag[T]

  sealed case class KeyPair[A](privateKey: PrivateKey[A], publicKey: PublicKey[A])
  object KeyPair {
    def apply[A](jPrivateKey: JPrivateKey, jPublicKey: JPublicKey): KeyPair[A] =
      new KeyPair[A](PrivateKey[A](jPrivateKey), PublicKey[A](jPublicKey))
  }

  sealed trait TaggedPublicKey {
    type KeyRepr
    def is: Is[KeyRepr, JPublicKey]
  }

  sealed trait TaggedPrivateKey {
    type KeyRepr
    def is: Is[KeyRepr, JPrivateKey]
  }

  protected val PublicKey$$ : TaggedPublicKey = new TaggedPublicKey {
    type KeyRepr = JPublicKey
    def is = Is.refl[JPublicKey]
  }
  protected val PrivateKey$$ : TaggedPrivateKey = new TaggedPrivateKey {
    override type KeyRepr = JPrivateKey

    override def is = Is.refl[JPrivateKey]
  }

  type PrivateKey[A] = PrivateKey$$.KeyRepr
  type PublicKey[A] = PublicKey$$.KeyRepr

  object PublicKey {
    @inline def apply[A](key: JPublicKey): PublicKey[A] = PublicKey$$.is.flip.coerce(key)
    @inline def toJavaPublicKey[A](key: PublicKey[A]): JPublicKey = PublicKey$$.is.coerce(key)
  }

  object PrivateKey {
    @inline def apply[A](key: JPrivateKey): PrivateKey[A] = PrivateKey$$.is.flip.coerce(key)
    @inline def toJavaPublicKey[A](key: PrivateKey[A]): JPrivateKey = PrivateKey$$.is.coerce(key)
  }

}
