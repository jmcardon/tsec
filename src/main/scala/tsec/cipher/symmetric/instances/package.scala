package tsec.cipher.symmetric

import javax.crypto.{SecretKey => JSecretKey}

import cats.effect.IO
import com.softwaremill.tagging._
import fs2.util.NonFatal

import scala.concurrent.ExecutionContext

package object instances {
  type JEncryptionKey[T] = JSecretKey @@ T

  implicit class IOOps(val io: IO.type) {
    def forkAsync[A](ec: ExecutionContext)(thunk: => A): IO[A] =
      IO.async[A] { cb =>
        try ec.execute(() => cb(Right(thunk)))
        catch { case NonFatal(e) => cb(Left(e)) }
      }
  }
}
