package tsec.common

import java.util.{ArrayDeque => Q}

/** ThreadLocal optimization for JCA and BC
  * `.getInstance()` methods tend to be expensive, and most of the methods
  * are not thread-safe, so this allows for some optimization.
  *
  * @tparam A
  */
protected[tsec] sealed trait QueueAlloc[A] {
  protected[tsec] val local: ThreadLocal[Q[A]]

  /** Enqueue into our threadlocal
    * @param v
    */
  def enqueue(v: A): Unit = local.get().addLast(v)

  /** May possibly be null
    * @return
    */
  def dequeue: A = local.get().poll()
}

object QueueAlloc {
  def apply[A](elems: List[A]): QueueAlloc[A] = {
    val q = new Q[A](elems.length)
    elems.foreach(q.add)
    new QueueAlloc[A] {
      val local: ThreadLocal[Q[A]] = new ThreadLocal[Q[A]] {
        override def initialValue(): Q[A] =
          q
      }
    }
  }
}
