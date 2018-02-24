package tsec.mac

import javax.crypto.{SecretKey => JSecretKey}
import java.security.MessageDigest
import java.util.concurrent.{ConcurrentLinkedQueue => JQueue}
import javax.crypto.Mac

import cats.{Monad, MonadError}
import cats.effect.Sync
import cats.instances.either._
import cats.syntax.all._
import tsec.common._
import tsec.mac.core._

package object imports {

  type MacErrorM[A] = Either[Throwable, A]

  trait MacKeyGenerator[A] extends JKeyGenerator[A, MacSigningKey, MacKeyBuildError]

  type MacSigningKey[A] = MacSigningKey.Type[A]

  object MacSigningKey {
    type Base$$1
    trait Tag$$1 extends Any
    type Type[A] <: Base$$1 with Tag$$1

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

  abstract class JCAMac[F[_]: Monad, A](tl: JQueue[Mac])(implicit macTag: JCAMacTag[A])
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

  object JCAMac {
    def sync[F[_], A](
        numInstances: Int = 10
    )(implicit tag: JCAMacTag[A], F: Sync[F]): JCAMac[F, A] = {
      val queue = new JQueue[Mac]()
      var i     = 0
      while (i < numInstances) {
        queue.add(Mac.getInstance(tag.algorithm))
        i += 1
      }
      new JCAMac[F, A](queue) {
        def catchF[C](thunk: => C): F[C] = F.delay(thunk)
      }
    }

    def monadError[F[_], A](
        numInstances: Int = 10
    )(implicit tag: JCAMacTag[A], F: MonadError[F, Throwable]): JCAMac[F, A] = {
      val queue = new JQueue[Mac]()
      var i     = 0
      while (i < numInstances) {
        queue.add(Mac.getInstance(tag.algorithm))
        i += 1
      }
      new JCAMac[F, A](queue) {
        def catchF[C](thunk: => C): F[C] = F.catchNonFatal(thunk)
      }
    }

  }

  implicit def gen[F[_]: Sync, A: JCAMacTag]: JCAMac[F, A] = JCAMac.sync[F, A]()
  implicit def genEither[A: JCAMacTag]: JCAMac[MacErrorM, A] =
    JCAMac.monadError[MacErrorM, A]()

}
