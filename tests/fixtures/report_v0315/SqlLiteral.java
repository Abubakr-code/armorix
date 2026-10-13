class SqlLiteral {
  void remove(java.util.UUID userId) {
    jdbc.update("delete from answer where user_id=?", userId);
  }
}
