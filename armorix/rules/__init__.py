from .appsec import (AutoescapeOff, CsrfExempt, FileInclusion, HardcodedSigningKey, InsecureCookie, InsecurePermissions, InsecureRandom,
                     MassAssignment, PrototypePollution, RegexInjection, TempFileRace, Xxe)
from .code_exec import CodeInjection, CommandInjection
from .infra import ActionsInjection, ActionsPwnRequest, ContainerPrivileged, DockerfileRisk, TerraformRisk
from .memory import AllocOverflow, BufferOverflow, FormatString, ShellCommandC, UseAfterFree
from .config import DebugEnabled, InsecureCors, JwtNoVerify, TlsVerifyDisabled, UnsafeDeserialization, WeakHash
from .secrets import HardcodedSecret
from .sqli import SqlInjection
from .web import NoSqlInjection, OpenRedirect, PathTraversal, ReflectedXss, Ssrf, TemplateInjection

ALL_RULES = [
    SqlInjection(), NoSqlInjection(), CommandInjection(), CodeInjection(), TemplateInjection(),
    ReflectedXss(), PathTraversal(), Ssrf(), OpenRedirect(), UnsafeDeserialization(),
    HardcodedSecret(), JwtNoVerify(), InsecureCors(), TlsVerifyDisabled(), DebugEnabled(), WeakHash(),
    MassAssignment(), PrototypePollution(), RegexInjection(), InsecureCookie(), InsecureRandom(), HardcodedSigningKey(), Xxe(),
    AutoescapeOff(), CsrfExempt(), InsecurePermissions(), TempFileRace(), FileInclusion(),
    # C / C++
    BufferOverflow(), UseAfterFree(), FormatString(), AllocOverflow(), ShellCommandC(),
    # CI / containers / cloud
    ActionsInjection(), ActionsPwnRequest(), DockerfileRisk(), ContainerPrivileged(), TerraformRisk(),
]

# Files without a telling extension that rules still want to read (matched on the lower-cased name).
TEXT_FILES = {"dockerfile", "containerfile", "jenkinsfile", "procfile"}
