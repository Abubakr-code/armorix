// Demo only: use-after-free in a session cleanup path.
void cleanup_session(Session* s) {
    audit_log(s->id);
    delete s;
    metrics.inc("closed");
    s->last_ping = now();
}
