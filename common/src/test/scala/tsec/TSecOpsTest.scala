package tsec
import cats.effect.IO
import tsec.common._
class TSecOpsTest extends TestSpec {

  behavior of "TSec ops"

  it should "convert Float properly" in {
    forAll { (value: Float) =>
      val convert = value.toBytes

      convert.toFloatUnsafe mustBe value
      convert.toFloat[IO].unsafeRunSync() mustBe value
    }
  }

  it should "convert Double properly" in {
    forAll { (value: Double) =>
      val convert = value.toBytes

      convert.toDoubleUnsafe mustBe value
      convert.toDouble[IO].unsafeRunSync() mustBe value
    }
  }

  it should "convert Long properly" in {
    forAll { (value: Long) =>
      val convert = value.toBytes

      convert.toLongUnsafe mustBe value
      convert.toLong[IO].unsafeRunSync() mustBe value
    }
  }

  it should "convert Short properly" in {
    forAll { (value: Short) =>
      val convert = value.toBytes

      convert.toShortUnsafe mustBe value
      convert.toShort[IO].unsafeRunSync() mustBe value
    }
  }

  it should "convert Int properly" in {
    forAll { (value: Int) =>
      val convert = value.toBytes

      convert.toIntUnsafe mustBe value
      convert.toInt[IO].unsafeRunSync() mustBe value
    }
  }

}
