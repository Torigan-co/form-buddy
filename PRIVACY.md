# Privacy policy

**Form Buddy collects nothing.**

That is the whole policy, but here is the detail, because a program that reads
your keystrokes owes you a precise answer rather than a reassuring one.

## What leaves your computer

Nothing. There is no network code in Form Buddy at all — no accounts, no sync,
no update check, no crash reporting, no analytics, no telemetry. It does not
open a socket. You can confirm this yourself: the entire program is one file,
[`source/FormBuddy.py`](source/FormBuddy.py).

## What is stored, and where

Only the answers you deliberately save — the things you got tired of typing
into forms. They are kept on your own machine, one encrypted file per person:

```
%APPDATA%\FormBuddy\users\<name>.fbvault
```

The contents are encrypted with AES-GCM. The key is derived from your password
using scrypt, and **the password itself is never stored anywhere** — not in
plain text, not hashed, not obscured. It exists only in memory while the app is
unlocked. A wrong password produces the wrong key and the file simply refuses
to open.

This also means nobody can recover it for you, including us.

Alongside that, a small settings file records your theme, your chosen shortcut
and which side the sidebar sits on. It contains no personal data.

## About the keyboard

Form Buddy installs a global keyboard hook. It has to: that is how it notices
you tapping `Alt` twice. It also reads the text box you are focused on, through
the standard Windows UI Automation interface, so it can work out what the form
is asking for.

While the suggestion strip is switched on, Form Buddy also reads the word you
are part-way through typing, twice a second, so it can offer anything that
matches. It reads that word from the box itself through UI Automation — it
does not keep a record of your keystrokes to reconstruct it.

None of this is stored. Keystrokes are examined for the shortcut and
discarded. The word under the caret is compared against your own saved
answers and then forgotten. The label of the box you are in is used to pick an
answer and then forgotten. Nothing is written to a log, and nothing is sent
anywhere.

If you would rather it did not read as you type, turn the suggestion strip off
in Settings; everything else keeps working, and the app then only looks at a
box when you tap the shortcut.

Mechanically this overlaps with what a keylogger does, which is why antivirus
software sometimes flags it. The difference is entirely in what happens next,
and that difference is auditable in the source.

## Removing everything

Delete the folder `%APPDATA%\FormBuddy` and the program file. Nothing is left
behind — no registry keys, no services, no scheduled tasks.

## Contact

Open an issue on [the repository](https://github.com/Torigan-co/form-buddy),
or contact Torigan through [torigan.com](https://torigan.com).
