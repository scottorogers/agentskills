# ai-memory

Cross-chat memory protocol: a MEMORY block the user carries between conversations, and the
rules for using and maintaining it (`SAVE`, `MEMORY?`, `FORGET: <thing>`).

## Install globally

```sh
cp -r skills/ai-memory ~/.claude/skills/ai-memory
```

The skill loads on demand. To make the protocol always-on and give the block a home, also add
a MEMORY section to the bottom of `~/.claude/CLAUDE.md`:

```
=== MEMORY — updated never ===
ABOUT ME:
WORK & PROJECTS:
PEOPLE:
PREFERENCES:
DECISIONS & FACTS:
OPEN THREADS:
=== END MEMORY ===
```

In chat surfaces where instructions can't be edited, paste the block as the first message
instead — the skill treats both the same.
