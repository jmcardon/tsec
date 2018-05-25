package tsec.keyrotation

import java.security.KeyStore

import cats.Applicative
import cats.effect.Sync
import cats.syntax.flatMap._
import fs2.async.Ref

abstract class KeyStrategy[F[_], K[_], A] {
  def retrieveKey: F[K[A]]
}

object StaticKeyStrategy {
  def apply[F[_]]: StaticKSBuilder[F] = new StaticKSBuilder[F]()

  private[tsec] final class StaticKSBuilder[F[_]](val dummy: Boolean = false) extends AnyVal {
    def apply[K[_], A](key: K[A])(implicit F: Applicative[F]): KeyStrategy[F, K, A] = new KeyStrategy[F, K, A] {
      override val retrieveKey: F[K[A]] = F.pure(key)
    }
  }
}

object JavaKeystoreStrategy {
  def fromKey[F[_]]: JavaKSBuilder[F] = new JavaKSBuilder[F]()

  private[tsec] final class JavaKSBuilder[F[_]](val dummy: Boolean = false) extends AnyVal {
    def apply[K[_], A](keystore: KeyStore, alias: String, password: Array[Char], build: Array[Byte] => F[K[A]])(
        implicit F: Sync[F]
    ): KeyStrategy[F, K, A] = new KeyStrategy[F, K, A] {
      def retrieveKey: F[K[A]] = F.delay(keystore.getKey(alias, password)).flatMap(b => build(b.getEncoded))
    }
  }
}

object RefStrategy {
  def apply[F[_]]: RefBuilder[F] = new RefBuilder[F]

  private[tsec] final class RefBuilder[F[_]](val dummy: Boolean = false) extends AnyVal {
    def apply[K[_], A](r: Ref[F, K[A]]): KeyStrategy[F, K, A] = new KeyStrategy[F, K, A] {
      def retrieveKey: F[K[A]] = r.get
    }
  }
}
