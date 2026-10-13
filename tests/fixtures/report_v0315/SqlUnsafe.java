class SqlUnsafe {
  void remove(HttpServletRequest request) {
    String id = request.getParameter("id");
    jdbc.update("delete from answer where user_id=" + id);
  }
}
