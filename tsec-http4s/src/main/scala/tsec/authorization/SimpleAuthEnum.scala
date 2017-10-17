package tsec.authorization
import io.circe.Decoder.Result
import io.circe._
import io.circe.syntax._

import scala.reflect.ClassTag

/** Dead simple typed enum with explicitly handled enumeration error
  * It also provides an implicit decoder/encoder for serialization into json.
  *
  * @tparam T the abstract type to enumerate, subclass style
  * @tparam Repr the representation type. i.e string, int, double, whatever.
  */
abstract class SimpleAuthEnum[T, Repr: Decoder: Encoder](implicit primtive: AuthPrimitive[Repr]) {
  implicit val authEnum: SimpleAuthEnum[T, Repr] = this

  val getRepr: T => Repr

  protected val values: AuthGroup[T]

  /** Since `Repr` does not come necessarily with a classtag,this is necessary, unfortunately*/
  private lazy val reprValues = primtive.unBoxedFromRepr[T](getRepr, values)

  val orElse: T

  def fromRepr(r: Repr): T = {
    val ix: Int = reprValues.indexOf(r)
    if (ix >= 0)
      values(ix)
    else
      orElse
  }

  @inline def contains(elem: T): Boolean = values.contains(elem)

  def viewAll(implicit classTag: ClassTag[T]): AuthGroup[T] = {
    val arr = new Array[T](values.length)
    values.copyToArray(arr)
    AuthGroup.unsafeFromArray[T](arr)
  }

  def toList: List[T] = values.toList

  implicit lazy val decoder: Decoder[T] = new Decoder[T] {
    def apply(c: HCursor): Result[T] = c.as[Repr].map(fromRepr)
  }

  implicit lazy val encoder: Encoder[T] = new Encoder[T] {
    def apply(a: T): Json = getRepr(a).asJson
  }

  implicit final def subClDecoder[A <: T](implicit singleton: A): Decoder[A] =
    new Decoder[A] {
      def apply(c: HCursor): Result[A] = c.as[T].flatMap {
        case a if a == singleton =>
          Right(singleton) //It's ok to do reference equality, since it should be singletons anyway
        case _ => Left(DecodingFailure("Improperly typed", Nil))
      }
    }

  implicit final def subCLEncoder[A <: T](implicit singleton: T): Encoder[A] = new Encoder[A] {
    def apply(a: A): Json = encoder(a)
  }
}
