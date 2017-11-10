package tsec.authentication

import java.time.Instant

import scala.concurrent.duration.FiniteDuration

/** Authenticators represent something similar to a
  * Token: Some piece of Id that you can use to identify a user with.
  * The only thing all authenticators have in common is that they all
  * have some eventual expiry date, as well as _possibly_ a lastTouched
  * date.
  *
  * An Authenticator can be a bearer token, a JWT, an encrypted
  * cookie or a signed cookie in TSec.
  *
  */
trait Authenticator[I] {
  val identity: I
  val expiry: Instant
  val lastTouched: Option[Instant]

  def isExpired(now: Instant): Boolean = expiry.isBefore(now)
  def isTimedout(now: Instant, timeOut: FiniteDuration): Boolean =
    lastTouched.exists(
      _.plusSeconds(timeOut.toSeconds)
        .isBefore(now)
    )
}
