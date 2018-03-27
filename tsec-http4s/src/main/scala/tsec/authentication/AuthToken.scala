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
trait AuthToken[A] {
  def expiry(a: A): Instant
  def lastTouched(a: A): Option[Instant]

  def isExpired(a: A, now: Instant): Boolean = expiry(a).isBefore(now)
  def isTimedOut(a: A, now: Instant, timeOut: FiniteDuration): Boolean =
    lastTouched(a).exists(
      _.plusSeconds(timeOut.toSeconds)
        .isBefore(now)
    )
}
