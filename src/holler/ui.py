"""Terminal front-end for the headless chat client."""

import asyncio
import sys
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.patch_stdout import patch_stdout
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel

from holler.client import Client

HELP_TEXT = "Type a message and press Enter. Commands: /who, /quit"


class TerminalUI:
    """Interactive terminal UI: prompt at the bottom, messages printed above.

    Uses prompt_toolkit so incoming messages never clobber the line being
    typed, and falls back to plain line-reading when stdin is not a TTY.
    """

    def __init__(self, client: Client):
        self.client = client
        self.console = Console(force_terminal=sys.stdout.isatty() or None)
        self._session: Optional[PromptSession] = None
        self._typing_users: "list[str]" = []
        client.on_event = self._on_event

    async def run(self):
        """Runs the full lifecycle: connect, chat loop, disconnect."""
        self.console.print(Panel("[bold cyan]holler[/]", expand=False))
        if self.client.join_id:
            self.console.print(f"[cyan]Connecting to room {self.client.join_id}…[/]")
        try:
            await self.client.start()
            if self.client.join_id:
                self.console.print(f"[dim]Online: {', '.join(self.client.online)}[/]")
            self.console.print(f"[dim]{HELP_TEXT}[/]")
            if sys.stdin.isatty():
                await self._prompt_loop()
            else:
                await self._plain_loop()
        finally:
            await self.client.stop()
            self.console.print("\n[yellow]Disconnected[/]")

    # ── input loops ───────────────────────────────────────────────────────────

    async def _prompt_loop(self):
        session: PromptSession = PromptSession()
        self._session = session

        def on_text_changed(buf):
            if buf.text:
                self.client.notify_typing()

        session.default_buffer.on_text_changed += on_text_changed

        with patch_stdout(raw=True):
            while self.client.running:
                try:
                    text = await session.prompt_async("> ", bottom_toolbar=self._toolbar)
                except KeyboardInterrupt:
                    break
                except EOFError:
                    break
                if not await self._dispatch(text):
                    break

    async def _plain_loop(self):
        loop = asyncio.get_running_loop()
        while self.client.running:
            try:
                line = await loop.run_in_executor(None, sys.stdin.readline)
            except (EOFError, KeyboardInterrupt):
                break
            if not line:
                break
            if not await self._dispatch(line.rstrip("\n")):
                break

    async def _dispatch(self, text: str) -> bool:
        """Handles one line of input. Returns False to exit the loop."""
        text = text.strip()
        if not text:
            return True
        if text.lower() in ("q", "/q", "/quit", "quit", "exit"):
            return False
        if text.lower() == "/who":
            self.console.print(f"[dim]Online: {', '.join(self.client.online)}[/]")
            return True
        await self.client.send_chat(text)
        return True

    # ── event rendering ───────────────────────────────────────────────────────

    def _toolbar(self):
        if not self._typing_users:
            return None
        names = ", ".join(self._typing_users)
        verb = "is" if len(self._typing_users) == 1 else "are"
        return f" {names} {verb} typing…"

    def _refresh_prompt(self):
        if self._session is not None:
            app = self._session.app
            try:
                if app.is_running:
                    app.invalidate()
            except Exception:
                pass

    def _on_event(self, kind: str, payload: dict):
        if kind == "chat":
            style = "green" if payload["username"] == self.client.username else "cyan"
            self.console.print(
                f"[dim]{escape(payload.get('wall') or '')}[/] "
                f"[{style}]{escape(payload['username'])}[/]: {escape(payload['text'])}"
            )
        elif kind == "info":
            self.console.print(f"[green]✓ {escape(payload['text'])}[/]")
        elif kind == "error":
            self.console.print(f"[red]✗ {escape(payload['text'])}[/]")
        elif kind == "room":
            self.console.print(f"\n[bold]Room ID:[/] [yellow]{payload['room_id']}[/]")
            self.console.print("[dim]Share this with peers to invite them.[/]\n")
        elif kind == "typing":
            self._typing_users = [u for u in payload["users"] if u != self.client.username]
            self._refresh_prompt()
