package tsec

import io.circe.Printer
import io.circe._
import io.circe.syntax._

package object jwt {
  val JWTPrinter = Printer(preserveOrder = true, dropNullValues = true, "")

  sealed trait JWTAudience {
    def toList: List[String]
  }
  case class JWTSingleAudience(value: String) extends JWTAudience {
    def toList = List(value)
  }
  case class JWTListAudience(values: List[String]) extends JWTAudience {
    def toList = values
  }

  implicit val audienceDecoder: Decoder[JWTAudience] = { c: HCursor =>
    c.as[String] match {
      case Right(a) => Right(JWTSingleAudience(a))
      case _        => c.as[List[String]].map(JWTListAudience(_))
    }
  }


  implicit val audienceEncoder: Encoder[JWTAudience] = new Encoder[JWTAudience] {
    def apply(a: JWTAudience): Json = a match {
      case JWTSingleAudience(value) => value.asJson
      case JWTListAudience(values) => values.asJson
    }
  }

}
