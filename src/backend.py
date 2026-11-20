from typing import Optional, Protocol


class CrackerBackend(Protocol):
    def crack(
        self, handshake_path: str, wordlist_path: str, display_essid: str
    ) -> Optional[dict[str, str]]:
        """Crack every network in one capture.

        Returns ``{essid: password}`` for what was recovered (empty when the
        attack ran but found nothing), or ``None`` when the backend itself could
        not run, which asks the caller to try the next backend.
        """
        ...
