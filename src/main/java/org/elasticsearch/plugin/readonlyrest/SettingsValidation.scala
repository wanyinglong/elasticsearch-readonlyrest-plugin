package org.elasticsearch.plugin.readonlyrest

import com.google.common.base.CaseFormat
import org.elasticsearch.common.settings.Setting
import org.elasticsearch.common.settings.Setting.Property._

object SettingsValidation {

  def mkRuleName(s: String): String = CaseFormat.LOWER_CAMEL.to(CaseFormat.LOWER_UNDERSCORE, s.split('.').last.replace("Rule", ""))

  private[readonlyrest] val prefix: String = "readonlyrest."
  private[readonlyrest] val VERBOSITY = Setting.simpleString(prefix + "verbosity", NodeScope)
  private[readonlyrest] val ENABLED = Setting.boolSetting(prefix + "enable", false, NodeScope)
  private[readonlyrest] val FORBIDDEN_RESPONSE = Setting.simpleString(prefix + "response_if_req_forbidden", NodeScope)
  private[readonlyrest] val sslPrefix = prefix + "ssl."
  private[readonlyrest] val SSL_ENABLED = Setting.boolSetting(sslPrefix + "enable", false, NodeScope)
  private[readonlyrest] val SSL_KSTORE_FILE = Setting.simpleString(sslPrefix + "keystore_file", NodeScope)
  private[readonlyrest] val SSL_KSTORE_PASS = Setting.simpleString(sslPrefix + "keystore_pass", NodeScope)
  private[readonlyrest] val SSL_K_PASS = Setting.simpleString(sslPrefix + "key_pass", NodeScope)

  import collection.JavaConverters._

  def getSettings: java.util.List[Setting[_]] = {
    val fixed = List(ENABLED, VERBOSITY, FORBIDDEN_RESPONSE, SSL_ENABLED, SSL_K_PASS, SSL_KSTORE_FILE, SSL_KSTORE_PASS)

    def listRules(p: String): List[Setting[java.util.List[String]]] = {
      val ruleNames = List(
        "indices",
        "methods",
        "hosts",
        "groups",
        "api_keys",
        "actions"
      )
      (0 to 100).map { i =>
        ruleNames.map { name =>
          Setting.listSetting[String](p + i + "." + name, new java.util.ArrayList[String](), (e => e.toString), NodeScope)
        }
      }.toList.flatten
    }

    def stringRules(p: String): List[Setting[_]] = {
      val ruleNames = List(
        "type",
        "name",
        "username",
        "kibana_access",
        "auth_key",
        "auth_key_sha1",
        "uri_re"
      )
      (0 to 100).map { i =>
        ruleNames.map(name => Setting.simpleString(p + i + "." + name, NodeScope))
      }.toList.flatten
    }


    def intRules(p: String): List[Setting[_]] = {
      val ruleNames = List(
        "maxBodyLength"
      )
      (0 to 100).map { i =>
        ruleNames.map(name => Setting.intSetting(p + i + "." + name, -1, NodeScope))
      }.toList.flatten
    }

    def booleanRules(p: String): List[Setting[_]] = {
      (0 to 100).map { i =>
        List(
          "accept_x-forwarded-for_header"
        ).map(name => Setting.boolSetting(p + i + "." + name, false, NodeScope))
      }.toList.flatten
    }
    val prefixes = List(prefix + "access_control_rules.", prefix + "users.")
    (fixed ++ prefixes.flatMap { p =>
      (booleanRules(p) ++ intRules(p) ++ listRules(p) ++ stringRules(p))
    }).asJava
  }
}
