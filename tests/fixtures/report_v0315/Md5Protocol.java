import java.security.MessageDigest;
class Md5Protocol {
  byte[] providerSignature(String signedFields) throws Exception {
    return MessageDigest.getInstance("MD5").digest(signedFields.getBytes());
  }
}
