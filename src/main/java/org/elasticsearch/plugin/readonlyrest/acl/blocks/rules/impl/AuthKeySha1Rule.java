package org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.impl;

import org.elasticsearch.ElasticsearchParseException;
import org.elasticsearch.common.hash.MessageDigests;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.readonlyrest.acl.blocks.rules.RuleNotConfiguredException;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Created by sscarduzio on 13/02/2016.
 */
public class AuthKeySha1Rule extends AuthKeyRule {

  public AuthKeySha1Rule(Settings s) throws RuleNotConfiguredException {
    super(s);
    try {
      authKey = new String(Base64.getDecoder().decode(authKey), StandardCharsets.UTF_8);
    } catch (Throwable e) {
      throw new ElasticsearchParseException("cannot parse configuration for: " + this.KEY);
    }
  }

  @Override
  protected boolean checkEqual(String provided) {
    try {
      String decodedProvided = new String(Base64.getDecoder().decode(provided), StandardCharsets.UTF_8);
      String shaProvided = new String(MessageDigests.sha1().digest(decodedProvided.getBytes(StandardCharsets.UTF_8)));
//      String shaProvided = Hashing.sha1().hashString(decodedProvided, StandardCharsets.UTF_8).toString();
      return authKey.equals(shaProvided);
    } catch (Throwable e) {
      return false;
    }
  }
}
