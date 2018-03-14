package tsec.mac

import java.security.MessageDigest
import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.{Mac, SecretKey => JSecretKey}

import cats.effect.Sync
import cats.instances.either._
import cats.syntax.all._
import cats.{Monad, MonadError}
import tsec.common._
import tsec.keygen.symmetric.{SymmetricKeyGen, SymmetricKeyGenAPI}

package object jca {

  type MacErrorM[A] = Either[Throwable, A]

  trait MacKeyGenerator[A] extends SymmetricKeyGenAPI[A, MacSigningKey]

  type MacSigningKey[A] = MacSigningKey.Type[A]

  type MacKeyGen[F[_], A] = SymmetricKeyGen[F, A, MacSigningKey]

  protected[tsec] trait JCAMacTag[T] extends CryptoTag[T]

  object JCAMacTag {
    @inline def apply[T](implicit M: JCAMacTag[T]): JCAMacTag[T] = M
  }

  object MacSigningKey {
    type Base$$1
    trait Tag$$1 extends Any
    type Type[A] <: Base$$1 with Tag$$1
    @inline def apply[A](key: JSecretKey): MacSigningKey[A] = key.asInstanceOf[MacSigningKey[A]]
    @inline def fromJavaKey[A: JCAMacTag](key: JSecretKey): MacSigningKey[A] = key.asInstanceOf[MacSigningKey[A]]
    @inline def toJavaKey[A: JCAMacTag](key: MacSigningKey[A]): JSecretKey   = key.asInstanceOf[JSecretKey]
    def subst[A]: SKPartiallyApplied[A]                                      = new SKPartiallyApplied[A]()

    private[tsec] class SKPartiallyApplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[JSecretKey]): F[MacSigningKey[A]] = value.asInstanceOf[F[MacSigningKey[A]]]
    }

    def unsubst[A]: PartiallyUnapplied[A] = new PartiallyUnapplied[A]

    private[tsec] final class PartiallyUnapplied[A](val dummy: Boolean = true) extends AnyVal {
      def apply[F[_]](value: F[MacSigningKey[A]]): F[JSecretKey] = value.asInstanceOf[F[JSecretKey]]
    }
  }

  final class SigningKeyOps[A](val key: MacSigningKey[A]) extends AnyVal {
    def toJavaKey(implicit m: JCAMacTag[A]): JSecretKey = MacSigningKey.toJavaKey[A](key)
  }

  implicit final def _macSigningOps[A](key: MacSigningKey[A]): SigningKeyOps[A] = new SigningKeyOps[A](key)

  abstract class JCAMessageAuth[F[_]: Monad, A](tl: JQueue[Mac])(implicit macTag: JCAMacTag[A])
      extends MessageAuth[F, A, MacSigningKey]
      with CanCatch[F] {

    private def genInstance: F[Mac] = catchF {
      val inst: Mac = tl.poll()
      if (inst != null)
        inst
      else
        Mac.getInstance(macTag.algorithm)
    }

    def sign(content: Array[Byte], key: MacSigningKey[A]): F[MAC[A]] =
      for {
        instance <- genInstance
        _        <- catchF(instance.init(MacSigningKey.toJavaKey[A](key)))
        fin      <- catchF(instance.doFinal(content))
        _        <- catchF(tl.add(instance))
      } yield MAC[A](fin)

    def verify(toSign: Array[Byte], signed: MAC[A], key: MacSigningKey[A]): F[Boolean] =
      sign(toSign, key).map(MessageDigest.isEqual(signed, _))

  }

  object JCAMessageAuth {
    def sync[F[_], A](
        numInstances: Int = 10
    )(implicit tag: JCAMacTag[A], F: Sync[F]): JCAMessageAuth[F, A] = {
      val queue = new JQueue[Mac]()
      var i     = 0
      while (i < numInstances) {
        queue.add(Mac.getInstance(tag.algorithm))
        i += 1
      }
      new JCAMessageAuth[F, A](queue) {
        def catchF[C](thunk: => C): F[C] = F.delay(thunk)
      }
    }

    def monadError[F[_], A](
        numInstances: Int = 10
    )(implicit tag: JCAMacTag[A], F: MonadError[F, Throwable]): JCAMessageAuth[F, A] = {
      val queue = new JQueue[Mac]()
      var i     = 0
      while (i < numInstances) {
        queue.add(Mac.getInstance(tag.algorithm))
        i += 1
      }
      new JCAMessageAuth[F, A](queue) {
        def catchF[C](thunk: => C): F[C] = F.catchNonFatal(thunk)
      }
    }

  }

  implicit def gen[F[_]: Sync, A: JCAMacTag]: JCAMessageAuth[F, A] = JCAMessageAuth.sync[F, A]()
  implicit def genEither[A: JCAMacTag]: JCAMessageAuth[MacErrorM, A] =
    JCAMessageAuth.monadError[MacErrorM, A]()

}
