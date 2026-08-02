---
name: ai-memory
description: "Persistent cross-chat memory — carry, use, and maintain the user's MEMORY block so nothing is lost between conversations. Use whenever the user types SAVE, MEMORY?, or 'FORGET: <thing>'; whenever a message contains a '=== MEMORY — updated ... ===' block; when the user asks what you remember, tells you to remember or forget something, or asks you to update your memory; and before answering anything that depends on background from past chats (clients, people, amounts, dates, preferences, open threads)."
---

# AI Memory Protocol

Chat AIs forget everything the moment a conversation ends. This skill fixes that with one artifact: a **MEMORY block** the user carries between chats and you maintain for them.

## Where memory lives

The MEMORY block reaches you one of two ways:

1. **In your instructions** — a MEMORY section at the bottom of the user's global `CLAUDE.md` (or project instructions, or a chat's custom instructions).
2. **Pasted as the first message** of a chat, when the user can't edit instructions.

Treat both identically. If the block lives in a file you can edit, update that file silently on SAVE **and** still output the block — the user may be carrying it elsewhere too. Never announce the edit; see the SAVE output rule.

If no block has appeared in this conversation, you have no memory of the user. Say so when asked; do not reconstruct one.

## Using memory

- **Silently and naturally.** Never say "according to my memory" or recite facts back. Just be someone who knows them.
- **Commit, don't hedge.** When a request matches something in MEMORY, use it by name — clients, people, amounts, dates. If memory identifies the thing uniquely, act on it; no "if you mean…".
- **Current chat wins.** MEMORY is true background, but anything the user says now overrides it.
- **Never invent a memory.** If something isn't in MEMORY and hasn't come up in this chat, say you don't have it. Don't guess, don't infer a plausible answer, don't fill a gap with something that "sounds like them".

## What goes into memory

The single most important rule: **memory stores what the user said and what they explicitly signed off on — nothing else.**

- Your own suggestions, plans, options, and advice never enter memory unless the user clearly adopted them: "let's do that", "booked", "agreed", "yes, that one".
- Something the user implied but didn't state may be stored only if marked `(inferred)`.
- Their words in their meaning. Don't sharpen "the week of the 8th" into exact dates they never gave, and don't upgrade "maybe" into "planned".
- **Never store secrets** — passwords, card numbers, API keys, tokens — even if pasted. Never store anything the user told you to forget.

## Commands

### SAVE — the end-of-chat ritual

Do these three steps in order, silently:

1. **Delete the dead.** Anything that resolved or ended this chat — invoice paid, project shipped, person left the project, trip taken — loses its line in **every** section. A resolved item has no line at all. Never a line saying it's "paid", "done", "resolved", "shipped". That's history, and history doesn't live in memory.
2. **Merge the living.** Add new facts. Where a new fact updates an old one, replace the old line rather than appending beside it.
3. **Output only the finished MEMORY block.** No preamble, no commentary, no "here's your updated memory", nothing after the block. The user copy-pastes your entire output.

### MEMORY?

Show the current MEMORY block exactly as you hold it, then a short list of what from this chat would be added on SAVE. (This command is the one that permits commentary — the list is the point.)

### `FORGET: <thing>`

Remove it from memory, then output the updated block exactly like SAVE — block only, nothing else. A forgotten thing never comes back, even if it appears in a later summary of the same chat.

## Block format (strict)

```
=== MEMORY — updated <date> ===
ABOUT ME: ...
WORK & PROJECTS: ...
PEOPLE: ...
PREFERENCES: ...
DECISIONS & FACTS: ...
OPEN THREADS: ...
=== END MEMORY ===
```

Keep all six headings, in this order, even if a section is thin.

## Writing rules

- **Facts, not transcripts.** One line per item, compressed.
- **Date anything that can go stale**, e.g. "(as of Jul 2026)".
- **The header date** is today's date if you genuinely know it. If you don't, write `unknown` and let the user fill it in. Never substitute some other date — not a deadline, not a guess, not the date of the last SAVE.
- **Merge, don't append.** A new fact that updates an old one replaces its line.
- **Delete the dead.** Writing "X is paid / done / resolved" anywhere in the block is a failure. Memory is what's true and useful going forward.
- **Hard cap: 250 words** for the whole block. Over the cap, keep what matters most going forward and drop the rest.

## Self-check before emitting a block

Run these four questions every time, and fix anything that fails:

1. Is every line something the user said or signed off on — nothing of yours that they didn't adopt?
2. Does any line describe something that's now finished? Delete it.
3. Does the header date follow the date rule?
4. Is the block under 250 words, in the exact six-section format, with no secrets?
