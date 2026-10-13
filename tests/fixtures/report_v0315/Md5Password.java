import java.security.MessageDigest;
class Md5Password {
  byte[] hashPassword(String password) throws Exception {
    return MessageDigest.getInstance("MD5").digest(password.getBytes());
  }
}
