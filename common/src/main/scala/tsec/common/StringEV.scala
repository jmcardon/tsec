package tsec.common

import cats.evidence.Is

trait StringEV[A] {

  def from(a: String): A

  def to(a: A): String

}

trait IsString {
  type I <: String

  val is: Is[I, String]
}