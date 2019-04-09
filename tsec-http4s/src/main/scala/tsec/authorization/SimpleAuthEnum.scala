package tsec.authorization

import cats.{Eq, MonadError}
import cats.syntax.all._
import io.circe.Decoder.Result
import io.circe._
import io.circe.syntax._
import tsec.common.TSecError

import scala.reflect.ClassTag

/** Dead simple typed enum with explicitly handled enumeration error
  * It also provides an implicit decoder/encoder for serialization into json.
  *
  * @tparam T the abstract type to enumerate, subclass style
  * @tparam Repr the representation type (i.e., string, int, double, ...)
  */
abstract class SimpleAuthEnum[T, @specialized(Specializable.Integral) Repr: Decoder: Encoder: ClassTag: Eq] {
  import SimpleAuthEnum._

  implicit val authEnum: SimpleAuthEnum[T, Repr] = this

  def getRepr(t: T): Repr

  protected val values: AuthGroup[T]

  /** Since `Repr` does not come necessarily with a ClassTag, this is necessary, unfortunately */
  private lazy val reprValues: Array[Repr] = {
    val n = new Array[Repr](values.length)
    var i = 0
    while (i < values.length) {
      n(i) = getRepr(values(i))
      i += 1
    }
    n
  }

  @inline def ixFromRepr(r: Repr): Int = {
    var i: Int = 0
    while (i < reprValues.length) {
      if (reprValues(i) === r)
        return i

      i += 1
    }
    -1
  }

  def unsafeFromRepr(r: Repr): T = fromRepr(r).fold(throw _, identity)

  def fromReprF[F[_]](r: Repr)(implicit F: MonadError[F, Throwable]): F[T] =
    F.fromEither(fromRepr(r))

  def fromRepr(r: Repr): Either[InvalidAuthorization, T] = {
    val ix = ixFromRepr(r)
    if (ix >= 0)
      Right(values(ix))
    else
      Left(InvalidAuthorization)
  }

  @inline def contains(elem: T): Boolean = values.contains(elem)

  def viewAll(implicit classTag: ClassTag[T]): AuthGroup[T] = {
    val arr = new Array[T](values.length)
    values.copyToArray(arr, 0, values.length)
    AuthGroup.unsafeFromArray[T](arr)
  }

  def toList: List[T] = values.toList

  lazy val cachedDecodingFailure = DecodingFailure(InvalidAuthorization.cause, Nil)

  /** Avoid the extra map from
    * using `safeFromRepr.andThen`
    */
  private def codecFromRepr(r: Repr): Either[DecodingFailure, T] = {
    val ix = ixFromRepr(r)
    if (ix >= 0)
      Right(values(ix))
    else
      Left(cachedDecodingFailure)
  }

  implicit lazy val decoder: Decoder[T] = new Decoder[T] {
    def apply(c: HCursor): Result[T] =
      c.as[Repr].flatMap(codecFromRepr)
  }

  implicit lazy val encoder: Encoder[T] = new Encoder[T] {
    def apply(a: T): Json = getRepr(a).asJson
  }
}

object SimpleAuthEnum {
  type InvalidAuthorization = InvalidAuthorization.type

  case object InvalidAuthorization extends TSecError {
    def cause: String = "Invalid Authorization"
  }
}
