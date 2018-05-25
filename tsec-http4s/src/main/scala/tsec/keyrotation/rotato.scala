package tsec.keyrotation

import cats.effect._
import cats.syntax.functor._
import cats.syntax.flatMap._
import fs2.Stream
import fs2.async.Ref
import fs2.async.mutable.Signal
import tsec.cipher.symmetric.jca.SecretKey
import tsec.keygen.symmetric.SymmetricKeyGen
import tsec.mac.jca.MacSigningKey

import scala.concurrent.ExecutionContext
import scala.concurrent.duration.FiniteDuration

abstract class TimedRotator[F[_], K[_], A](
    private[this] val timeout: FiniteDuration,
    private[this] val internal: Ref[F, K[A]],
    private[this] val T: Timer[F],
    private[this] val terminationSignal: Signal[F, Boolean]
)(implicit F: ConcurrentEffect[F], ec: ExecutionContext) {

  /** Return a KeyStrategy, which you can use for
    * instantiating an `Authenticator`
    *
    * @return key strategy
    */
  final def getStrategy: KeyStrategy[F, K, A] = RefStrategy[F](internal)

  /** Generate or fetch a new key.
    * In particular, this is a flexible signature in that you can
    * make `F[_]` be a network call.
    *
    */
  def generateNew: F[K[A]]

  /** Replace our key in our internal atomic reference */
  def rotateKey(): F[Unit] =
    for {
      newKey <- generateNew
      _      <- internal.setSync(newKey)
    } yield ()

  /** Return a stream of events wherein every emitted action is the evaluation
    * of a rotation
    */
  def rotatoStream: Stream[F, Unit] =
    Stream
      .repeatEval[F, Unit](T.sleep(timeout) >> rotateKey)
      .interruptWhen(terminationSignal)

  /** Consume the key rot stream concurrently and
    * fork it
    */
  def rotato: F[Unit] =
    F.start(T.shift >> rotatoStream.compile.drain).as(())

}

object InMemoryTimedRotator {

  def macKeyRotato[F[_]: ConcurrentEffect, A](
      timeout: FiniteDuration,
      T: Timer[F]
  )(
      implicit K: SymmetricKeyGen[F, A, MacSigningKey],
      ec: ExecutionContext
  ): Stream[F, TimedRotator[F, MacSigningKey, A]] =
    Stream
      .eval(for {
        key            <- K.generateKey
        newRef         <- Ref[F, MacSigningKey[A]](key)
        shutdownSignal <- Signal[F, Boolean](false)
      } yield (newRef, shutdownSignal))
      .flatMap {
        case (ref, signal) =>
          Stream
            .emit(new TimedRotator[F, MacSigningKey, A](timeout, ref, T, signal) {
              def generateNew: F[MacSigningKey[A]] = K.generateKey
            })
            .onFinalize(signal.set(true))
      }

  def macKeyRotatoEffect[F[_]: ConcurrentEffect, A](
      timeout: FiniteDuration,
      T: Timer[F]
  )(
      implicit K: SymmetricKeyGen[F, A, MacSigningKey],
      ec: ExecutionContext
  ): F[(TimedRotator[F, MacSigningKey, A], F[Unit])] =
    (for {
      key            <- K.generateKey
      newRef         <- Ref[F, MacSigningKey[A]](key)
      shutdownSignal <- Signal[F, Boolean](false)
    } yield (newRef, shutdownSignal)).map {
      case (ref, signal) =>
        (new TimedRotator[F, MacSigningKey, A](timeout, ref, T, signal) {
          def generateNew: F[MacSigningKey[A]] = K.generateKey
        }, signal.set(true))
    }

  def cipherKeyRotato[F[_]: ConcurrentEffect, A](
      timeout: FiniteDuration,
      T: Timer[F]
  )(
      implicit K: SymmetricKeyGen[F, A, SecretKey],
      ec: ExecutionContext
  ): Stream[F, TimedRotator[F, SecretKey, A]] =
    Stream
      .eval(for {
        key            <- K.generateKey
        newRef         <- Ref[F, SecretKey[A]](key)
        shutdownSignal <- Signal[F, Boolean](false)
      } yield (newRef, shutdownSignal))
      .flatMap {
        case (ref, signal) =>
          Stream
            .emit(new TimedRotator[F, SecretKey, A](timeout, ref, T, signal) {
              def generateNew: F[SecretKey[A]] = K.generateKey
            })
            .onFinalize(signal.set(true))
      }

  def cipherKeyRotatoEffect[F[_]: ConcurrentEffect, A](
      timeout: FiniteDuration,
      T: Timer[F]
  )(
      implicit K: SymmetricKeyGen[F, A, SecretKey],
      ec: ExecutionContext
  ): F[(TimedRotator[F, SecretKey, A], F[Unit])] =
    (for {
      key            <- K.generateKey
      newRef         <- Ref[F, SecretKey[A]](key)
      shutdownSignal <- Signal[F, Boolean](false)
    } yield (newRef, shutdownSignal)).map {
      case (ref, signal) =>
        (new TimedRotator[F, SecretKey, A](timeout, ref, T, signal) {
          def generateNew: F[SecretKey[A]] = K.generateKey
        }, signal.set(true))
    }

}
