package tsec

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatestplus.scalacheck.ScalaCheckPropertyChecks
import org.scalatest.matchers.must.Matchers

trait TestSpec extends AnyFlatSpec with Matchers with ScalaCheckPropertyChecks
