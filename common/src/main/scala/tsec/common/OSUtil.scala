package tsec.common

import java.security.{AccessController, PrivilegedAction}
import java.util.Locale

object OSUtil {

  lazy val isWindows: Boolean = {
    OSUtil.getSystemProperty("os.name", "").toLowerCase(Locale.US).contains("win")
  }

  lazy val isOsx: Boolean = {
    val osName = OSUtil
      .getSystemProperty("os.name", "")
      .toLowerCase(Locale.US)
      .replaceAll("[^a-z0-9]+", "")

    osName.startsWith("macosx") || osName.startsWith("osx")
  }

  def getSystemProperty(key: String, default: String): String = {
    if (key == null) throw new NullPointerException("key")
    if (key.isEmpty) throw new IllegalArgumentException("key must not be empty.")
    try if (System.getSecurityManager == null) System.getProperty(key)
    else
      AccessController.doPrivileged(new PrivilegedAction[String]() {
        override def run: String = System.getProperty(key)
      })
    catch {
      case e: SecurityException =>
        default
    }
  }

}
