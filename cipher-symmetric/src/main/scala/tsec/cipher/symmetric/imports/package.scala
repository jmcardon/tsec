package tsec.cipher.symmetric

import cats.effect.IO

import scala.concurrent.ExecutionContext
import scala.util.control.NonFatal

package object imports {

  implicit class IOOps(val io: IO.type) {
    def forkAsync[A](ec: ExecutionContext)(thunk: => A): IO[A] =
      IO.async[A] { cb =>
        try ec.execute(() => cb(Right(thunk)))
        catch { case NonFatal(e) => cb(Left(e)) }
      }
  }
}
