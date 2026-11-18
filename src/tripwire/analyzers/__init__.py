"""The static analysers. Each one reads a Package and returns Evidence."""

from .credentials import CredentialsAnalyzer
from .depconfusion import DepConfusionAnalyzer
from .install_hooks import InstallHooksAnalyzer
from .network import NetworkAnalyzer
from .obfuscation import ObfuscationAnalyzer
from .typosquat import TyposquatAnalyzer

ANALYZERS = (
    InstallHooksAnalyzer(),
    ObfuscationAnalyzer(),
    NetworkAnalyzer(),
    CredentialsAnalyzer(),
    TyposquatAnalyzer(),
    DepConfusionAnalyzer(),
)
ANALYZER_NAMES = tuple(a.name for a in ANALYZERS)

__all__ = ["ANALYZERS", "ANALYZER_NAMES"]
