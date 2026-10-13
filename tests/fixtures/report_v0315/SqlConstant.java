class SqlConstant {
  void remove(java.util.UUID userId) {
    String owned = "select id from section where user_id=?";
    jdbc.update("delete from answer where section_id in (" + owned + ")", userId);
  }
}
