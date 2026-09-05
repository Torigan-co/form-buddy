# Form Buddy

**Version 1.1.4** — by [Torigan](https://torigan.com) · released 5 September 2026

Fill any form on Windows with two taps of `Alt`.

Form Buddy fills in forms for you. Save your details once, then click any text
box in any program and tap `Alt` twice — the right answer is typed straight in.
It works through Windows itself rather than through a browser, so it reaches
the forms extensions can't: PDFs, Word documents, desktop applications. Your
answers stay encrypted on your own machine behind a password that is never
stored anywhere, and the whole thing is one portable file with nothing to
install.

## Download

**[FormBuddy.exe](../../raw/main/FormBuddy.exe)** — 22 MB, Windows 10 or 11.

Double-click it. There is no installer, no account and no setup. Copy it to a
USB stick and it runs the same on any Windows PC.

---

## The first time

You are asked for a name and a password. That password encrypts your answers
and **is never stored anywhere** — not written down, not hashed, not
remembered. It becomes the key to your file and nothing more.

That also means nobody can recover it for you. Write it down somewhere safe.

Then fill in the answers you use often — name, email, phone, address,
qualifications, referees. Blank ones are simply never offered.

---

## The two ways to use it

### Tap Alt twice

Click into a box and tap `Alt` twice. A search window opens in the middle of
the screen with the cursor already in it. Type, press `Enter`, done.

| What is in the box | What a double-tap does |
| --- | --- |
| Nothing typed | The window opens with the best guess for that box on top |
| A word, e.g. `ema` | One clear match fills straight in, no window. Several open the window, already searching |
| Highlighted text | Only the highlighted part is replaced |
| Placeholders like `fb=email` | Every one of them is filled, in order |
| `fm=last name=Perera` | Saves that answer, then clears the line away |

If you were not in a text box at all, `Enter` copies the answer to the
clipboard instead, so you always get it either way.

**It never wipes a box.** Whatever is already there stays, so you can put a
first name in, tap again, and add the last name after it.

### The sidebar

A thin strip sits on the edge of your screen. Touch it with the mouse and the
sidebar opens; move away and it hides.

Clicking an answer there **copies it**. The sidebar never types into your
form — only `Alt Alt` writes — so a stray click cannot overwrite anything you
are working on. Press and hold an answer to edit it on the spot.

The `⋯` button holds every other option: add an answer, the Answers, Settings,
Help and About windows, import, export, reload, which side the sidebar sits
on, whether it is listening, lock or switch person, and quit.

---

## Fill a whole letter at once

Write `fb=` followed by the name of an answer wherever you want one dropped
in, then tap `Alt` twice once, anywhere in that box:

```
Dear Sir, my name is fb=last name and you can reach me
at fb=email. Please call fb=phone if needed.
Regards, fb=first name
```

Every placeholder is filled, top to bottom. Where a name is ambiguous —
`fb=reference` when you have three of them — it stops there, opens the search
window for that one, and carries on by itself once you pick.

Only the words that actually name an answer are used, so
`fb=last name and thanks` fills in the last name and leaves `and thanks`
exactly where it is.

---

## Your answers

Search at the top of the Answers window, everything grouped by category
underneath — Personal, Contact, Address, Work, Education, Links, Documents,
Writing, Referees.

- **Search** matches labels, categories, other names for a field, and values.
- **The dropdown** on each row moves an answer to another category. Pick
  **New category…** to invent your own.
- **The ✕** removes one. An answer you invented is deleted; a built-in one is
  only emptied, ready for next time.
- **Import / Export** move everything to another PC. Import only takes
  non-empty values, so it tops up rather than blanks.

Anything added the fast way — `fm=lucky number=7` — lands in **Uncategorised**
so you can file it later instead of being asked in the moment.

Answers, Settings, Help and About are separate windows, never tabs, and only
one is open at a time.

---

## Settings

| Setting | What it does |
| --- | --- |
| **Theme** | **Match Windows** follows your light/dark setting and borrows your Windows accent colour. Dark, Light and Midnight override it. |
| **Shortcut** | `Alt Alt`, `Ctrl Ctrl` or `Shift Shift` |
| **Stop a lone Alt tap opening menu bars** | Windows treats a single `Alt` as "focus the menu bar". This swallows it. `Alt+Tab` and every other combination keep working |
| **Speed of the double tap** | 200–900 ms between the two taps |
| **How sure it must be before filling on its own** | Higher asks more often, lower fills more often |

The **Help** window has the whole manual with worked examples.

---

## The icon

One shape throughout, and the colour tells you the state.

| Green | Running and listening |
| --- | --- |
| **Red** | Switched off |
| **Orange** | The program file itself |

---

## Privacy

Everything is encrypted on your own machine, one file per person:

```
%APPDATA%\FormBuddy\users\<name>.fbvault
```

The file name is the only readable part — that is how the lock screen lists
who exists before anyone types a password. Inside is AES-GCM ciphertext, with
the key derived from your password using scrypt.

**There is no network code in this program at all.** No account, no sync, no
telemetry, nothing sent anywhere. `FormBuddy.exe` itself carries no personal
data, so sharing the file shares nothing about you.

---

## Where it works

Anywhere Windows exposes a text box, which is nearly everywhere: Edge, Chrome
and Firefox web forms, Word, Excel, Outlook, PDF form fields, Electron apps
such as Slack and VS Code, and ordinary desktop dialogs.

---

## Licence

MIT — see [LICENSE](LICENSE).
