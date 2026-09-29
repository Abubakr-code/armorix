from .code_exec import CodeInjection, CommandInjection
from .config import DebugEnabled, InsecureCors, JwtNoVerify, TlsVerifyDisabled, UnsafeDeserialization, WeakHash
from .secrets import HardcodedSecret
from .sqli import SqlInjection
from .web import NoSqlInjection, OpenRedirect, PathTraversal, ReflectedXss, Ssrf, TemplateInjection

ALL_RULES = [
    SqlInjection(), NoSqlInjection(), CommandInjection(), CodeInjection(), TemplateInjection(),
    ReflectedXss(), PathTraversal(), Ssrf(), OpenRedirect(), UnsafeDeserialization(),
    HardcodedSecret(), JwtNoVerify(), InsecureCors(), TlsVerifyDisabled(), DebugEnabled(), WeakHash(),
]
