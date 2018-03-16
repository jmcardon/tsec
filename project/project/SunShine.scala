package tsec.build

object SunShine {
  import sbt._

  lazy val `tools.jar` =
    sys.env.get("JAVA_HOME")
      .map(jh => new File(s"$jh/lib/tools.jar"))
      .filter(_.canRead)
      .map(Attributed.blank)

  lazy val canWeUseToolsDotJar_? = ( // yes, iff ...
      // it exists
      `tools.jar`.isDefined
      // and we're not in IntelliJ
    && !sys.env.getOrElse("XPC_SERVICE_NAME", "").toLowerCase.contains("intellij")
  )

}
