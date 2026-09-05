"""Form Buddy - one file, no installer, nothing to set up.

Click into any box on any form, tap Alt twice, and your answer is typed in.
There is also a slim panel that hides at the edge of the screen: touch the
edge with the mouse and it opens.

Everything you save lives in your Windows AppData folder, under FormBuddy.
It never leaves this machine: the program has no network code at all.
"""
from __future__ import annotations

import ctypes
import base64
import json
import os
import queue
import re
import secrets
import sys
import threading
import time
import webbrowser
import tkinter as tk
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from ctypes import wintypes
from dataclasses import dataclass, field as dc_field
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import uiautomation as auto
import pystray
from PIL import Image, ImageDraw


# ==========================================================================
#  WHERE THINGS LIVE ON DISK, AND EVERY SETTING
# ==========================================================================
# Paths + persisted settings for Form Buddy.

APP_NAME = "Form Buddy"
APP_VERSION = "1.1.4"
APP_AUTHOR = "Torigan"
APP_WEBSITE = "torigan.com"
APP_RELEASED = "5 September 2026"
_DIR_NAME = "FormBuddy"

DEFAULT_SETTINGS = {
    # How the buddy is summoned. "double_alt" = tap Alt twice, quickly.
    "hotkey": "double_alt",            # double_alt | double_ctrl | double_shift
    "double_tap_ms": 450,              # max gap between the two taps
    # Swallow lone Alt taps so Windows/Chrome do not pop their menu bar
    # every time you summon the buddy. Only affects Alt pressed on its own;
    # Alt+Tab, Alt+F4 and every other Alt combo keep working.
    "suppress_solo_alt": True,
    # Matching confidence. >= threshold and ahead of runner-up by margin -> fill silently.
    "auto_fill_threshold": 78,
    "auto_fill_margin": 12,
    "type_delay_ms": 1,                # per-character delay while typing
    "start_enabled": True,
    "show_toasts": True,
    # The dock down the side of the screen. It hides itself; a thin handle
    # sits on the screen edge and opens it when the mouse touches it.
    "panel_visible": False,
    "panel_hide_delay_ms": 800,
    "panel_side": "left",              # left | right
    # The strip above the taskbar that suggests answers while you type.
    "suggest_bar": True,
    "theme": "system",                 # system | dark | light | midnight
}


def data_dir() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    d = Path(base) / _DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


SETTINGS_PATH = data_dir() / "settings.json"


def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as fh:
            s.update(json.load(fh))
    except FileNotFoundError:
        pass
    except (OSError, ValueError):
        pass
    return s


def save_settings(settings: dict) -> None:
    with open(SETTINGS_PATH, "w", encoding="utf-8") as fh:
        json.dump(settings, fh, indent=2)


# ==========================================================================
#  THE VAULT
# ==========================================================================
# Answers are personal, so they are kept encrypted, one file per person.
#
#   %APPDATA%\FormBuddy\users\<name>.fbvault
#
# The file name is the only thing stored in the clear, which is how the login
# screen can list who exists without anyone having typed a password yet.
# Everything inside is AES-GCM ciphertext.
#
# THE PASSWORD IS NEVER STORED, anywhere, in any form - not hashed, not
# obscured, not remembered. It is fed through scrypt to derive the key, the
# key lives in memory for as long as the app is unlocked, and that is all.
# A wrong password is not "checked" against anything; it simply produces the
# wrong key, and AES-GCM's own authentication refuses to decrypt. Which also
# means a forgotten password cannot be recovered by us or by anybody else.

USERS_DIR = data_dir() / "users"
VAULT_SUFFIX = ".fbvault"
LEGACY_PROFILE = data_dir() / "profile.json"

# scrypt cost. Deliberately slow: about a third of a second per attempt here,
# which you pay once at login and an attacker pays on every guess.
SCRYPT_N = 2 ** 17
SCRYPT_R = 8
SCRYPT_P = 1
VAULT_FORMAT = "formbuddy-vault-1"

_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]{0,40}$")


class WrongPassword(Exception):
    """The password did not open this vault."""


class VaultMissing(Exception):
    """No vault file for that person."""


def valid_username(name: str) -> bool:
    """Usable as a file name, and readable when it is one."""
    return bool(_SAFE_NAME.match((name or "").strip()))


def vault_path(username: str):
    return USERS_DIR / ((username or "").strip() + VAULT_SUFFIX)


def list_users() -> List[str]:
    """Who has a vault here. Needs no password - it is just a directory listing."""
    try:
        names = [p.name[:-len(VAULT_SUFFIX)] for p in USERS_DIR.iterdir()
                 if p.name.endswith(VAULT_SUFFIX)]
    except (OSError, FileNotFoundError):
        return []
    return sorted(names, key=str.lower)


def _derive(password: str, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R,
                  p=SCRYPT_P).derive(password.encode("utf-8"))


def write_vault(username: str, password_key: bytes, payload: dict) -> None:
    """Encrypt `payload` into this person's vault, replacing what was there."""
    key, salt = password_key
    nonce = os.urandom(12)
    clear = json.dumps(payload).encode("utf-8")
    box = AESGCM(key).encrypt(nonce, clear, VAULT_FORMAT.encode("utf-8"))
    envelope = {
        "format": VAULT_FORMAT,
        "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "data": base64.b64encode(box).decode("ascii"),
    }
    USERS_DIR.mkdir(parents=True, exist_ok=True)
    path = vault_path(username)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(envelope, fh)
    os.replace(tmp, path)          # never leave a half-written vault behind


def read_vault(username: str, password: str, key=None):
    """Open a vault. Returns (payload, key), or just the payload when a key
    is passed in.

    The key comes back so the rest of the session can save without asking for
    the password again.
    """
    reading_with_key = key is not None
    path = vault_path(username)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            envelope = json.load(fh)
    except FileNotFoundError:
        raise VaultMissing(username)
    except (OSError, ValueError) as exc:
        raise WrongPassword("that vault file is damaged: %s" % exc)

    try:
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        box = base64.b64decode(envelope["data"])
        if key is None:
            derived = Scrypt(salt=salt, length=32,
                             n=int(envelope.get("n", SCRYPT_N)),
                             r=int(envelope.get("r", SCRYPT_R)),
                             p=int(envelope.get("p", SCRYPT_P))).derive(
                                 password.encode("utf-8"))
            key = (derived, salt)
        clear = AESGCM(key[0]).decrypt(nonce, box, VAULT_FORMAT.encode("utf-8"))
    except KeyError as exc:
        raise WrongPassword("that vault file is missing %s" % exc)
    except Exception:
        # InvalidTag, and anything else, means the same thing to you.
        raise WrongPassword("wrong password")
    payload = json.loads(clear.decode("utf-8"))
    return payload if reading_with_key else (payload, key)


def create_vault(username: str, password: str, payload=None):
    """Start a new person off. Returns the session key."""
    salt = os.urandom(16)
    key = (_derive(password, salt), salt)
    write_vault(username, key, payload or {"fields": []})
    return key


def change_password(username: str, old: str, new: str):
    """Re-encrypt the same answers under a new password."""
    payload, _key = read_vault(username, old)
    salt = os.urandom(16)
    key = (_derive(new, salt), salt)
    write_vault(username, key, payload)
    return key


def _count_answers(payload) -> int:
    """How many answers in a payload actually hold something."""
    try:
        return len([f for f in payload.get("fields", [])
                    if (f.get("value") or "").strip()])
    except AttributeError:
        return 0


class Session:
    """Who is signed in, and the key that lets us read their answers.

    Both live in memory only. Quitting, locking or crashing loses the key,
    and there is nothing on disk to recover it from.
    """

    def __init__(self):
        self.username = None
        self.key = None

    @property
    def open(self) -> bool:
        return self.key is not None

    def start(self, username: str, key) -> None:
        self.username, self.key = username, key

    def end(self) -> None:
        self.username, self.key = None, None


SESSION = Session()


# ==========================================================================
#  YOUR ANSWER BOOK
# ==========================================================================
# The user's answer book: one entry per thing a form might ask for.

class Field:
    """A single answer, plus every label a form might use to ask for it."""

    __slots__ = ("key", "label", "value", "aliases", "avoid", "multiline",
                 "secret", "category")

    def __init__(self, key, label, value="", aliases=None, avoid=None,
                 multiline=False, secret=False, category=""):
        self.key = key
        self.label = label
        self.value = value
        self.aliases = list(aliases or [])
        # Labels that look similar but mean something else. A hit here
        # disqualifies the field entirely (keeps "username" off "full name").
        self.avoid = list(avoid or [])
        self.multiline = multiline
        self.secret = secret
        # Which group this belongs to in the answers window. Anything new
        # lands in "Uncategorised" until you decide otherwise.
        self.category = category or UNCATEGORISED

    def preview(self, width: int = 42) -> str:
        v = " ".join(self.value.split())
        if not v:
            return "(empty — add it in Edit answers)"
        if self.secret:
            return v[:2] + "*" * (len(v) - 4) + v[-2:] if len(v) > 4 else "*" * len(v)
        return v if len(v) <= width else v[: width - 1] + "…"

    def to_dict(self) -> dict:
        return {
            "key": self.key, "label": self.label, "value": self.value,
            "aliases": self.aliases, "avoid": self.avoid,
            "multiline": self.multiline, "secret": self.secret,
            "category": self.category,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Field":
        return cls(
            key=d.get("key", ""), label=d.get("label", d.get("key", "")),
            value=d.get("value", ""), aliases=d.get("aliases"), avoid=d.get("avoid"),
            multiline=bool(d.get("multiline")), secret=bool(d.get("secret")),
            category=d.get("category", ""),
        )


UNCATEGORISED = "Uncategorised"

# The groups the shipped answers arrive in. Users can add their own, and
# move anything anywhere; these are only a sensible starting point.
CAT_PERSONAL = "Personal"
CAT_CONTACT = "Contact"
CAT_ADDRESS = "Address"
CAT_WORK = "Work"
CAT_EDUCATION = "Education"
CAT_LINKS = "Links"
CAT_DOCUMENTS = "Documents"
CAT_WRITING = "Writing"
CAT_REFEREES = "Referees"

SHIPPED_CATEGORIES = [CAT_PERSONAL, CAT_CONTACT, CAT_ADDRESS, CAT_WORK,
                      CAT_EDUCATION, CAT_LINKS, CAT_DOCUMENTS, CAT_WRITING,
                      CAT_REFEREES, UNCATEGORISED]

# key -> category, for everything that ships with the app.
DEFAULT_CATEGORY = {
    "first_name": CAT_PERSONAL, "middle_name": CAT_PERSONAL,
    "last_name": CAT_PERSONAL, "full_name": CAT_PERSONAL,
    "dob": CAT_PERSONAL, "gender": CAT_PERSONAL,
    "nationality": CAT_PERSONAL,

    "email": CAT_CONTACT, "phone": CAT_CONTACT, "alt_phone": CAT_CONTACT,

    "address1": CAT_ADDRESS, "address2": CAT_ADDRESS, "city": CAT_ADDRESS,
    "state": CAT_ADDRESS, "zip": CAT_ADDRESS, "country": CAT_ADDRESS,

    "company": CAT_WORK, "company2": CAT_WORK, "job_title": CAT_WORK,
    "headline": CAT_WORK, "experience": CAT_WORK, "current_ctc": CAT_WORK,
    "expected_ctc": CAT_WORK, "notice_period": CAT_WORK, "skills": CAT_WORK,

    "university": CAT_EDUCATION, "degree": CAT_EDUCATION,
    "grad_year": CAT_EDUCATION, "bachelors": CAT_EDUCATION,
    "masters_ongoing": CAT_EDUCATION, "teaching_expertise": CAT_EDUCATION,
    "publications": CAT_EDUCATION, "achievements": CAT_EDUCATION,

    "linkedin": CAT_LINKS, "github": CAT_LINKS, "portfolio": CAT_LINKS,
    "medium": CAT_LINKS,

    "nic": CAT_DOCUMENTS, "passport": CAT_DOCUMENTS,

    "summary": CAT_WRITING, "cover_letter": CAT_WRITING,

    "references": CAT_REFEREES, "ref1_name": CAT_REFEREES,
    "ref1_email": CAT_REFEREES, "ref1_phone": CAT_REFEREES,
    "ref2_name": CAT_REFEREES, "ref2_email": CAT_REFEREES,
    "ref2_phone": CAT_REFEREES,
}


def default_fields() -> List[Field]:
    F = Field
    fields = [
        # --- identity -------------------------------------------------
        F("first_name", "First name", aliases=[
            "first name", "firstname", "given name", "fname", "forename",
            "first", "name first"],
          avoid=["last name", "middle name"]),
        F("middle_name", "Middle name", aliases=[
            "middle name", "middlename", "middle initial", "mname", "middle"]),
        F("last_name", "Last name", aliases=[
            "last name", "lastname", "surname", "family name", "lname",
            "second name", "last"],
          avoid=["first name"]),
        F("full_name", "Full name", aliases=[
            "full name", "fullname", "name", "your name", "complete name",
            "legal name", "candidate name", "applicant name", "name as per records"],
          avoid=["user name", "username", "login name", "file name", "company name",
                 "display name", "account name", "first name", "last name",
                 "middle name", "father name", "mother name", "nick name",
                 "college name", "school name", "university name", "brand name",
                 "product name", "domain name"]),
        F("email", "Email", aliases=[
            "email", "e mail", "email address", "email id", "mail id", "mail",
            "work email", "personal email", "contact email"]),
        F("phone", "Phone", aliases=[
            "phone", "phone number", "mobile", "mobile number", "mobile no",
            "contact number", "contact no", "cell", "cell phone", "telephone",
            "whatsapp number"],
          avoid=["alternate", "landline", "emergency"]),
        F("alt_phone", "Alternate phone", aliases=[
            "alternate phone", "alternate mobile", "secondary phone",
            "other phone", "landline", "emergency contact number"]),
        F("dob", "Date of birth", aliases=[
            "date of birth", "dob", "birth date", "birthdate", "birthday"]),
        F("gender", "Gender", aliases=["gender", "sex"]),
        F("nationality", "Nationality", aliases=[
            "nationality", "citizenship", "citizen of"]),

        # --- address --------------------------------------------------
        F("address1", "Address line 1", aliases=[
            "address", "address line 1", "address 1", "street address", "street",
            "house address", "current address", "permanent address",
            "residential address", "mailing address", "addr1"],
          avoid=["email address", "address line 2", "address 2", "ip address"]),
        F("address2", "Address line 2", aliases=[
            "address line 2", "address 2", "apartment", "apt", "suite", "unit",
            "landmark", "addr2", "locality", "area"]),
        F("city", "City", aliases=["city", "town", "city town", "district", "village"]),
        F("state", "State", aliases=["state", "province", "region", "state province"]),
        F("zip", "Postal code", aliases=[
            "zip", "zip code", "zipcode", "postal code", "postcode", "post code",
            "pin code", "pincode", "pin"]),
        F("country", "Country", aliases=["country", "nation", "country region"]),

        # --- work -----------------------------------------------------
        F("company", "Current company", aliases=[
            "company", "company name", "employer", "current employer",
            "current company", "organisation", "organization", "org name",
            "present company", "firm"]),
        F("job_title", "Job title", aliases=[
            "job title", "designation", "current designation", "position",
            "current role", "role", "job role", "title", "current position",
            "occupation"]),
        F("experience", "Years of experience", aliases=[
            "years of experience", "total experience", "work experience",
            "experience", "yoe", "exp in years", "relevant experience"]),
        F("current_ctc", "Current salary", aliases=[
            "current ctc", "current salary", "present salary",
            "current compensation", "existing ctc", "annual salary"]),
        F("expected_ctc", "Expected salary", aliases=[
            "expected ctc", "expected salary", "salary expectation",
            "desired salary", "expected compensation", "salary expected"]),
        F("notice_period", "Notice period", aliases=[
            "notice period", "availability", "joining time", "available from",
            "how soon can you join", "earliest start date"]),

        # --- links ----------------------------------------------------
        F("linkedin", "LinkedIn", aliases=[
            "linkedin", "linked in", "linkedin url", "linkedin profile",
            "linkedin link"]),
        F("github", "GitHub", aliases=[
            "github", "git hub", "github url", "github profile", "github link"]),
        F("portfolio", "Portfolio / website", aliases=[
            "portfolio", "website", "personal website", "portfolio url",
            "personal site", "web site", "blog", "portfolio link"]),

        # --- education ------------------------------------------------
        F("university", "University / college", aliases=[
            "university", "college", "school", "institute", "institution",
            "college name", "school name"]),
        F("degree", "Degree", aliases=[
            "degree", "qualification", "highest qualification", "course",
            "specialisation", "specialization", "major", "branch", "stream"]),
        F("grad_year", "Graduation year", aliases=[
            "graduation year", "year of passing", "passing year",
            "year of graduation", "passout year", "completion year"]),
        F("skills", "Skills", aliases=[
            "skills", "key skills", "technical skills", "core skills",
            "primary skills", "skill set"], multiline=True),

        # --- documents (previewed masked) -----------------------------
        F("nic", "NIC / national ID", aliases=[
            "nic", "nic number", "nic no", "national identity card",
            "national identity card number", "national id number",
            "identity card number", "id card number"], secret=True),
        F("passport", "Passport number", aliases=[
            "passport", "passport number", "passport no"], secret=True),

        # --- long form ------------------------------------------------
        F("summary", "About me / summary", aliases=[
            "about you", "about me", "summary", "profile summary", "bio",
            "tell us about yourself", "introduce yourself"], multiline=True),
        F("cover_letter", "Cover letter", aliases=[
            "cover letter", "covering letter", "why should we hire you",
            "why do you want to join", "message", "additional information",
            "anything else", "comments", "notes"], multiline=True),

        # --- academic / professional profile --------------------------
        F("headline", "Professional headline", aliases=[
            "headline", "professional headline", "profile headline",
            "tagline", "one line bio"]),
        F("company2", "Current company (industry)", aliases=[
            "industry employer", "current industry company",
            "software company", "secondary employer", "other current employer"]),
        F("bachelors", "Bachelor's degree", aliases=[
            "bachelor degree", "bachelors degree", "bachelors",
            "undergraduate degree", "ug degree", "bsc", "first degree"]),
        F("masters_ongoing", "Studies in progress", aliases=[
            "ongoing degree", "current studies", "currently studying",
            "postgraduate in progress", "studying at present"]),
        F("teaching_expertise", "Areas of teaching expertise", aliases=[
            "areas of teaching expertise", "teaching expertise",
            "teaching areas", "subjects taught", "modules taught",
            "areas of expertise", "teaching interests"], multiline=True),
        F("publications", "Research publications", aliases=[
            "publications", "research publications", "papers",
            "research papers", "publication list", "journal papers"],
          multiline=True),
        F("achievements", "Achievements / awards", aliases=[
            "achievements", "awards", "honours", "honors", "accomplishments",
            "awards and achievements", "prizes"], multiline=True),
        F("medium", "Medium profile", aliases=[
            "medium", "medium profile", "medium url", "medium blog"]),

        # --- referees -------------------------------------------------
        F("references", "References (all)", aliases=[
            "references", "referees", "reference details", "referee details"],
          multiline=True),
        F("ref1_name", "Reference 1 — name", aliases=[
            "reference name", "referee name", "reference 1 name",
            "referee 1 name", "first reference name", "name of referee"]),
        F("ref1_email", "Reference 1 — email", aliases=[
            "reference email", "referee email", "reference 1 email",
            "referee 1 email", "email of referee"]),
        F("ref1_phone", "Reference 1 — phone", aliases=[
            "reference phone", "referee phone", "reference 1 phone",
            "referee 1 phone", "reference contact number"]),
        F("ref2_name", "Reference 2 — name", aliases=[
            "reference 2 name", "referee 2 name", "second reference name"]),
        F("ref2_email", "Reference 2 — email", aliases=[
            "reference 2 email", "referee 2 email", "second reference email"]),
        F("ref2_phone", "Reference 2 — phone", aliases=[
            "reference 2 phone", "referee 2 phone", "second reference phone"]),
    ]
    for field in fields:
        field.category = DEFAULT_CATEGORY.get(field.key, UNCATEGORISED)
    return fields


class Profile:
    def __init__(self, fields: Optional[List[Field]] = None):
        self.fields: List[Field] = fields if fields is not None else default_fields()

    # -- persistence ---------------------------------------------------
    @classmethod
    def load(cls) -> "Profile":
        """Read the signed-in person's answers out of their vault."""
        if not SESSION.open:
            return cls()                       # locked: nobody's answers
        try:
            raw = read_vault(SESSION.username, None, key=SESSION.key)
        except Exception:
            return cls()
        return cls.from_payload(raw)

    @classmethod
    def from_payload(cls, raw: dict) -> "Profile":
        saved = {d.get("key"): d for d in raw.get("fields", [])}
        fields = []
        for base in default_fields():
            d = saved.pop(base.key, None)
            if d:
                # Keep the shipped aliases fresh; keep the user's value and extras.
                base.value = d.get("value", "")
                # A category the user set themselves wins over the shipped one.
                if d.get("category"):
                    base.category = d["category"]
                base.aliases.extend(
                    a for a in d.get("aliases", []) if a not in base.aliases)
            fields.append(base)
        # Whatever is left was either invented by the user or dropped from the
        # shipped set in a later version. Keep the ones holding an answer;
        # quietly retire the empty leftovers so the editor does not fill up
        # with fields nobody uses.
        for d in saved.values():
            if d and d.get("value", "").strip():
                fields.append(Field.from_dict(d))
        return cls(fields)

    def to_payload(self) -> dict:
        return {"fields": [f.to_dict() for f in self.fields]}

    def save(self) -> None:
        """Encrypt and write. Does nothing at all while locked."""
        if not SESSION.open:
            return
        write_vault(SESSION.username, SESSION.key, self.to_payload())

    # -- access --------------------------------------------------------
    def get(self, key: str) -> Optional[Field]:
        return next((f for f in self.fields if f.key == key), None)

    def categories(self) -> List[str]:
        """Every category in use, shipped ones first, Uncategorised last."""
        used = {f.category for f in self.fields if f.category}
        ordered = [c for c in SHIPPED_CATEGORIES if c in used and c != UNCATEGORISED]
        extra = sorted(c for c in used
                       if c not in SHIPPED_CATEGORIES)
        return ordered + extra + ([UNCATEGORISED] if UNCATEGORISED in used else [])

    def in_category(self, name: str) -> List[Field]:
        return [f for f in self.fields if f.category == name]

    def filled(self) -> List[Field]:
        return [f for f in self.fields if f.value.strip()]


# ==========================================================================
#  WORKING OUT WHICH ANSWER A BOX WANTS
# ==========================================================================
# Turn "what the form calls this box" into "which answer of mine goes here".
# 
# Everything a form can tell us about a box (its label, its HTML id, its
# placeholder, the text sitting next to it) is scored against every alias of
# every answer in the profile. Best score wins.

# How much we trust each source of a field's name. A visible <label> beats a
# guessed neighbour every time.
SOURCE_WEIGHT: Dict[str, float] = {
    "label": 1.00,        # UIA Name — usually the <label> or aria-label
    "id": 0.95,           # AutomationId — the HTML id/name attribute
    "placeholder": 0.92,  # HelpText / FullDescription
    "description": 0.86,  # LegacyIAccessible description/help
    "neighbour": 0.80,    # nearest static text before the box
}

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NOISE = re.compile(
    r"\b(please|enter|your|the|a|an|type|input|field|box|text|edit|required|"
    r"optional|here|kindly|provide|give)\b")


def normalize(text) -> str:
    """'firstName *' / 'Enter your First Name:' -> 'first name'."""
    if not text:
        return ""
    t = _CAMEL.sub(" ", str(text))
    t = re.sub(r"[^A-Za-z0-9]+", " ", t)
    t = re.sub(r"\s+", " ", t).strip().lower()
    t = _NOISE.sub(" ", t)
    return re.sub(r"\s+", " ", t).strip()


def _squash(s: str) -> str:
    return s.replace(" ", "")


def _alias_score(text: str, alias: str) -> float:
    """0-100 for how well `alias` describes `text` (both normalized)."""
    if not text or not alias:
        return 0.0

    a_tokens = alias.split()
    t_tokens = text.split()
    # Longer aliases are more specific, so let them edge out short ones.
    specificity = min(6.0, 2.0 * len(a_tokens))

    if text == alias:
        return 100.0

    squashed_t, squashed_a = _squash(text), _squash(alias)
    if squashed_t == squashed_a:                       # "firstname" vs "first name"
        return 97.0

    # Whole-phrase hit, e.g. alias "first name" inside "candidate first name".
    if re.search(r"\b%s\b" % re.escape(alias), text):
        extra = len(t_tokens) - len(a_tokens)
        return max(55.0, 90.0 - 5.0 * extra) + specificity

    # Run-together hit, e.g. alias "zip code" inside "billingzipcode".
    if len(squashed_a) >= 4 and squashed_a in squashed_t:
        extra = len(squashed_t) - len(squashed_a)
        return max(50.0, 82.0 - 1.5 * extra) + specificity

    # All words present but scattered: "name of the city" vs alias "city name".
    if len(a_tokens) > 1 and all(tok in t_tokens for tok in a_tokens):
        return 64.0 + specificity

    return 0.0


def score_field(field: Field, texts: Sequence[Tuple[str, str]]) -> Tuple[float, str]:
    """Best (score, matched_text) for one profile field across all clues."""
    normalized = [(src, normalize(t)) for src, t in texts]

    for _src, text in normalized:
        for bad in field.avoid:
            bad = normalize(bad)
            if bad and re.search(r"\b%s\b" % re.escape(bad), text):
                return 0.0, ""

    best, best_text = 0.0, ""
    for src, text in normalized:
        if not text:
            continue
        weight = SOURCE_WEIGHT.get(src, 0.75)
        for alias in field.aliases:
            s = _alias_score(text, normalize(alias)) * weight
            if s > best:
                best, best_text = s, text
    return min(best, 100.0), best_text


def rank(fields: Iterable[Field], texts: Sequence[Tuple[str, str]],
         only_filled: bool = True) -> List[Tuple[Field, float, str]]:
    """All candidate answers for a box, best first."""
    out = []
    for f in fields:
        if only_filled and not f.value.strip():
            continue
        score, matched = score_field(f, texts)
        if score > 0:
            out.append((f, score, matched))
    out.sort(key=lambda r: -r[1])
    return out


def is_confident(ranked: Sequence[Tuple[Field, float, str]],
                 threshold: float, margin: float) -> bool:
    """True when the top answer is both good and clearly ahead of the runner-up."""
    if not ranked or ranked[0][1] < threshold:
        return False
    runner_up = ranked[1][1] if len(ranked) > 1 else 0.0
    return ranked[0][1] - runner_up >= margin


MISS = 99          # _match_tier's "no hit at all"


def _match_tier(field: Field, q: str) -> int:
    """How good a free-text hit is. Lower is better; MISS means no hit.

    The ordering is what stops near-misses winning. "email" prefixes a word in
    both "Email" and "Reference 1 - email", but only the first *starts* with
    it, so only the first is what anybody means. Same reason "fir" is First
    name rather than "first reference name": a hit on the field's own label
    outranks one buried in its alternative names.
    """
    label, key = normalize(field.label), normalize(field.key)
    squashed_q = _squash(q)

    if label == q or _squash(label) == squashed_q:
        return 0
    if label.startswith(q) or _squash(label).startswith(squashed_q):
        return 1
    if any(word.startswith(q) for word in label.split()):
        return 2
    if key == q or _squash(key).startswith(squashed_q):
        return 3
    if any(word.startswith(q) for word in key.split()):
        return 4

    for alias in field.aliases:
        alias = normalize(alias)
        if alias == q:
            return 5
        if alias.startswith(q) or _squash(alias).startswith(squashed_q):
            return 6
    for alias in field.aliases:
        alias = normalize(alias)
        if any(word.startswith(q) for word in alias.split()):
            return 7
        if squashed_q in _squash(alias):
            return 8
    if squashed_q in _squash(label + " " + key):
        return 9
    return MISS


def is_filler(word: str) -> bool:
    """Words that carry no meaning in a field name, so a placeholder's name
    should stop before them rather than swallowing them."""
    return not normalize(word)


def search(fields: Iterable[Field], query: str) -> List[Field]:
    """Free-text filter for the type-to-search boxes, best matches first."""
    q = normalize(query)
    if not q:
        return list(fields)
    hits = [(_match_tier(f, q), f) for f in fields]
    hits = [(tier, f) for tier, f in hits if tier < MISS]
    hits.sort(key=lambda r: r[0])
    return [f for _tier, f in hits]


def sole_match(fields: Iterable[Field], query: str):
    """The one answer a typed word clearly means, or None if it is a toss-up.

    Only the best tier of hits counts: one field matching on its own label
    beats any number of fields that merely mention the word in an alias.
    """
    q = normalize(query)
    if not q:
        return None
    tiers = [(_match_tier(f, q), f) for f in fields]
    tiers = [(t, f) for t, f in tiers if t < MISS]
    if not tiers:
        return None
    best = min(t for t, _f in tiers)
    winners = [f for t, f in tiers if t == best]
    return winners[0] if len(winners) == 1 else None


# ==========================================================================
#  TYPING, AND A FEW WINDOW HELPERS
# ==========================================================================
# Synthetic keystrokes via SendInput.
# 
# Typing (rather than poking the value straight into the control) is what makes
# the buddy work everywhere — React, Angular and Flutter inputs all listen for
# real key events and would ignore a value written behind their back.

user32 = ctypes.WinDLL("user32", use_last_error=True)

INPUT_KEYBOARD = 1
KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

VK_BACK = 0x08
VK_TAB = 0x09
VK_RETURN = 0x0D
VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_ESCAPE = 0x1B
VK_SPACE = 0x20
VK_END = 0x23
VK_HOME = 0x24
VK_LEFT = 0x25
VK_UP = 0x26
VK_RIGHT = 0x27
VK_DOWN = 0x28
VK_DELETE = 0x2E
VK_LSHIFT = 0xA0
VK_RSHIFT = 0xA1
VK_LCONTROL = 0xA2
VK_RCONTROL = 0xA3
VK_LMENU = 0xA4
VK_RMENU = 0xA5
VK_F13 = 0x7C

# Stamped on every keystroke we synthesise so our own hook ignores them.
FORMBUDDY_TAG = 0x46425544  # "FBUD"


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]  # ULONG_PTR


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("padding", ctypes.c_byte * 32)]


class INPUT(ctypes.Structure):
    _fields_ = [("type", wintypes.DWORD), ("union", _INPUTUNION)]


def _kb(vk=0, scan=0, flags=0) -> INPUT:
    ki = KEYBDINPUT(wVk=vk, wScan=scan, dwFlags=flags, time=0,
                    dwExtraInfo=FORMBUDDY_TAG)
    return INPUT(type=INPUT_KEYBOARD, union=_INPUTUNION(ki=ki))


def _send(events) -> None:
    if not events:
        return
    arr = (INPUT * len(events))(*events)
    user32.SendInput(len(events), arr, ctypes.sizeof(INPUT))


def tap(vk: int, extended: bool = False) -> None:
    flags = KEYEVENTF_EXTENDEDKEY if extended else 0
    _send([_kb(vk=vk, flags=flags),
           _kb(vk=vk, flags=flags | KEYEVENTF_KEYUP)])


def key_up(vk: int) -> None:
    _send([_kb(vk=vk, flags=KEYEVENTF_KEYUP)])


# Arrows, Home/End, Insert/Delete are "extended" keys: without the flag some
# apps see a numeric-keypad key instead, and modifiers may not apply.
EXTENDED_VKS = {VK_LEFT, VK_UP, VK_RIGHT, VK_DOWN, VK_HOME, VK_END, VK_DELETE}


def chord(modifiers, vk: int) -> None:
    """e.g. chord([VK_CONTROL], ord('A')) for Ctrl+A."""
    flags = KEYEVENTF_EXTENDEDKEY if vk in EXTENDED_VKS else 0
    events = [_kb(vk=m) for m in modifiers]
    events += [_kb(vk=vk, flags=flags),
               _kb(vk=vk, flags=flags | KEYEVENTF_KEYUP)]
    events += [_kb(vk=m, flags=KEYEVENTF_KEYUP) for m in reversed(modifiers)]
    _send(events)


def backspace(count: int) -> None:
    """Rub out the characters the user typed as their search word."""
    if count <= 0:
        return
    events = []
    for _ in range(min(count, 200)):
        events.append(_kb(vk=VK_BACK))
        events.append(_kb(vk=VK_BACK, flags=KEYEVENTF_KEYUP))
    _send(events)


def type_text(text: str, delay_ms: int = 1) -> None:
    """Type any Unicode text — no keyboard-layout guessing needed."""
    delay = max(0, delay_ms) / 1000.0
    for ch in text:
        if ch == "\n":
            tap(VK_RETURN)
        elif ch == "\r":
            continue
        elif ch == "\t":
            tap(VK_TAB)
        else:
            code = ord(ch)
            # Characters outside the BMP arrive as a surrogate pair; SendInput
            # takes each 16-bit unit separately.
            units = ([code] if code <= 0xFFFF else
                     [0xD800 + ((code - 0x10000) >> 10),
                      0xDC00 + ((code - 0x10000) & 0x3FF)])
            for unit in units:
                _send([_kb(scan=unit, flags=KEYEVENTF_UNICODE),
                       _kb(scan=unit, flags=KEYEVENTF_UNICODE | KEYEVENTF_KEYUP)])
        if delay:
            time.sleep(delay)


def select_all_and_clear() -> None:
    """Empty the focused single- or multi-line box before typing into it."""
    chord([VK_CONTROL], ord("A"))
    time.sleep(0.01)
    tap(VK_DELETE, extended=True)
    time.sleep(0.01)


def release_alt_without_menu(alt_vk: int = VK_LMENU) -> None:
    """Let go of Alt without Windows treating it as "focus the menu bar".

    Windows only opens the menu when Alt goes down and up with nothing in
    between, so we slip an inert F13 in between first.
    """
    tap(VK_F13)
    key_up(alt_vk)
    key_up(VK_MENU)


# --- window helpers ---------------------------------------------------

def work_area():
    """The screen minus the taskbar: (left, top, right, bottom)."""
    rect = wintypes.RECT()
    SPI_GETWORKAREA = 0x0030
    if user32.SystemParametersInfoW(SPI_GETWORKAREA, 0, ctypes.byref(rect), 0):
        return rect.left, rect.top, rect.right, rect.bottom
    return (0, 0, user32.GetSystemMetrics(0), user32.GetSystemMetrics(1))


def set_foreground(hwnd: int) -> None:
    """Bring a window back to the front and give it the keyboard again."""
    try:
        user32.SetForegroundWindow(hwnd)
    except Exception:
        pass


def foreground_window() -> int:
    return user32.GetForegroundWindow()


def window_title(hwnd: int) -> str:
    length = user32.GetWindowTextLengthW(hwnd)
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(hwnd, buf, length + 1)
    return buf.value


def window_pid(hwnd: int) -> int:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def process_name(hwnd: int) -> str:
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(512)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return buf.value.rsplit("\\", 1)[-1]
        return ""
    finally:
        kernel32.CloseHandle(handle)


def cursor_pos():
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def make_non_activating(hwnd: int) -> None:
    """Stop a window from ever stealing focus from the form underneath."""
    GWL_EXSTYLE = -20
    WS_EX_NOACTIVATE = 0x08000000
    WS_EX_TOOLWINDOW = 0x00000080
    WS_EX_TOPMOST = 0x00000008
    get_ = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
    set_ = getattr(user32, "SetWindowLongPtrW", user32.SetWindowLongW)
    get_.restype = ctypes.c_ssize_t
    set_.restype = ctypes.c_ssize_t
    set_.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
    style = get_(hwnd, GWL_EXSTYLE)
    set_(hwnd, GWL_EXSTYLE,
         style | WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW | WS_EX_TOPMOST)


# ==========================================================================
#  THE GLOBAL DOUBLE-TAP LISTENER
# ==========================================================================
# Global low-level keyboard hook: detects the double-tap and, while the
# double-tap is detected here and nowhere else.

WH_KEYBOARD_LL = 13
WM_KEYDOWN, WM_KEYUP = 0x0100, 0x0101
WM_SYSKEYDOWN, WM_SYSKEYUP = 0x0104, 0x0105
LLKHF_INJECTED = 0x10

HOTKEY_VKS = {
    "double_alt": (VK_LMENU, VK_RMENU, VK_MENU),
    "double_ctrl": (VK_LCONTROL, VK_RCONTROL, 0x11),
    "double_shift": (VK_LSHIFT, VK_RSHIFT, 0x10),
}
HOTKEY_LABELS = {
    "double_alt": "Alt Alt",
    "double_ctrl": "Ctrl Ctrl",
    "double_shift": "Shift Shift",
}
_MODIFIERS = set(HOTKEY_VKS["double_alt"] + HOTKEY_VKS["double_ctrl"]
                 + HOTKEY_VKS["double_shift"] + (0x5B, 0x5C))  # + Win keys

class KBDLLHOOKSTRUCT(ctypes.Structure):
    _fields_ = [("vkCode", wintypes.DWORD), ("scanCode", wintypes.DWORD),
                ("flags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ctypes.c_size_t)]


HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_ssize_t, ctypes.c_int,
                              wintypes.WPARAM, wintypes.LPARAM)

# Without these, ctypes assumes 32-bit ints and chokes on the 64-bit lparam.
user32.SetWindowsHookExW.argtypes = [ctypes.c_int, HOOKPROC,
                                     wintypes.HINSTANCE, wintypes.DWORD]
user32.SetWindowsHookExW.restype = wintypes.HHOOK
user32.CallNextHookEx.argtypes = [wintypes.HHOOK, ctypes.c_int,
                                  wintypes.WPARAM, wintypes.LPARAM]
user32.CallNextHookEx.restype = ctypes.c_ssize_t
user32.UnhookWindowsHookEx.argtypes = [wintypes.HHOOK]


class HotkeyHook:
    """Runs the hook on its own thread with its own message pump."""

    def __init__(self, settings, on_trigger, on_suggest_key=None):
        self.settings = settings
        self.on_trigger = on_trigger          # called when the hotkey fires
        self.on_suggest_key = on_suggest_key  # Alt+arrow, while the strip is up
        self.suggest_visible = False
        self._alt_down = False
        self.enabled = True
        self._hook = None
        self._thread_id = None
        self._proc = HOOKPROC(self._callback)  # keep a strong reference
        self._solo = False        # no other key pressed since modifier went down
        self._mod_down = 0        # which modifier vk is currently held
        self._last_tap = 0.0

    # -- lifecycle -----------------------------------------------------
    def start(self) -> None:
        threading.Thread(target=self._run, name="formbuddy-hook",
                         daemon=True).start()

    def stop(self) -> None:
        if self._thread_id:
            user32.PostThreadMessageW(self._thread_id, 0x0012, 0, 0)  # WM_QUIT

    def _run(self) -> None:
        self._thread_id = ctypes.windll.kernel32.GetCurrentThreadId()
        self._hook = user32.SetWindowsHookExW(WH_KEYBOARD_LL, self._proc, None, 0)
        if not self._hook:
            raise OSError("could not install the keyboard hook "
                          f"(error {ctypes.get_last_error()})")
        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))
        user32.UnhookWindowsHookEx(self._hook)

    # -- the hook itself -----------------------------------------------
    def _callback(self, code, wparam, lparam):
        if code != 0:
            return user32.CallNextHookEx(None, code, wparam, lparam)

        kb = ctypes.cast(lparam, ctypes.POINTER(KBDLLHOOKSTRUCT)).contents
        # Never react to keystrokes we typed ourselves.
        if kb.dwExtraInfo == FORMBUDDY_TAG:
            return user32.CallNextHookEx(None, code, wparam, lparam)

        try:
            swallow = self._handle(wparam, kb)
        except Exception:
            swallow = False
        if swallow:
            return 1
        return user32.CallNextHookEx(None, code, wparam, lparam)

    def _handle(self, wparam, kb) -> bool:
        vk = kb.vkCode
        down = wparam in (WM_KEYDOWN, WM_SYSKEYDOWN)
        injected = bool(kb.flags & LLKHF_INJECTED)

        if not self.enabled or injected:
            return False

        # Remember whether Alt is held, so the suggestion strip can claim
        # Alt plus an arrow without disturbing a bare arrow key.
        if vk in (VK_LMENU, VK_RMENU, VK_MENU):
            self._alt_down = down

        if (self.suggest_visible and self._alt_down and down
                and self.on_suggest_key is not None):
            action = {VK_LEFT: "left", VK_RIGHT: "right",
                      VK_UP: "use", VK_RETURN: "use"}.get(vk)
            if action:
                self.on_suggest_key(action)
                return True          # do not let it reach the app underneath

        hotkey = self.settings.get("hotkey", "double_alt")
        trigger_vks = HOTKEY_VKS.get(hotkey, HOTKEY_VKS["double_alt"])

        if down:
            if vk in trigger_vks:
                if self._mod_down != vk:
                    self._mod_down = vk
                    self._solo = True
            elif vk not in _MODIFIERS:
                self._solo = False       # it became a combo, e.g. Alt+Tab
            return False

        # key up
        if vk not in trigger_vks:
            return False
        was_solo, self._solo, self._mod_down = self._solo, False, 0
        if not was_solo:
            return False

        now = time.monotonic()
        gap = self.settings.get("double_tap_ms", 450) / 1000.0
        fired = (now - self._last_tap) <= gap
        self._last_tap = 0.0 if fired else now
        if fired:
            threading.Thread(target=self.on_trigger, daemon=True).start()

        # Stop lone Alt taps from popping menu bars all over Windows.
        if hotkey == "double_alt" and self.settings.get("suppress_solo_alt", True):
            self._release_alt(vk)
            return True
        return False

    def _release_alt(self, vk: int) -> None:
        """Off-thread: never call SendInput from inside a hook callback."""
        threading.Thread(target=release_alt_without_menu,
                         args=(vk,), daemon=True).start()



# ==========================================================================
#  READING THE BOX YOU ARE SITTING IN
# ==========================================================================
# Read the box the user is sitting in: what it is called and what it holds.
# 
# Uses UI Automation, so it works the same in Chrome, Edge, Firefox, Electron
# apps, Office and plain Win32 dialogs.

auto.SetGlobalSearchTimeout(0.5)

# Rather than listing what can be typed into — which would leave out Word's
# document surface, an Excel cell, a PDF form box and every custom Electron
# widget — we list the handful of things that clearly cannot.
NON_EDITABLE_TYPES = {
    auto.ControlType.ButtonControl, auto.ControlType.CheckBoxControl,
    auto.ControlType.RadioButtonControl, auto.ControlType.MenuItemControl,
    auto.ControlType.MenuBarControl, auto.ControlType.MenuControl,
    auto.ControlType.TabItemControl, auto.ControlType.TreeItemControl,
    auto.ControlType.HyperlinkControl, auto.ControlType.ImageControl,
    auto.ControlType.SliderControl, auto.ControlType.ScrollBarControl,
    auto.ControlType.SeparatorControl, auto.ControlType.TitleBarControl,
    auto.ControlType.ToolBarControl, auto.ControlType.ProgressBarControl,
    auto.ControlType.StatusBarControl, auto.ControlType.HeaderControl,
    auto.ControlType.HeaderItemControl, auto.ControlType.TreeControl,
    auto.ControlType.CalendarControl, auto.ControlType.SplitButtonControl,
    auto.ControlType.ThumbControl, auto.ControlType.ToolTipControl,
}
# ...and these always win, even when the app labels them oddly.
EDITABLE_CLASS_HINTS = ("edit", "textbox", "textarea", "richedit", "input",
                        "scintilla", "chrome_renderwidget", "excel",
                        "_wwg",            # Word's document window
                        "netuihwnd")       # Office ribbon-era input surfaces
# Editable, but a whole document rather than one box.
DOCUMENT_CLASS_HINTS = ("_wwg", "richedit50w", "richeditd2dpt", "scintilla",
                        "excel", "notepad")


@dataclass
class FieldContext:
    """Everything we learned about the focused box."""
    control: object = None
    hwnd: int = 0
    app: str = ""
    window_title: str = ""
    control_type: str = ""
    class_name: str = ""
    editable: bool = False
    # True only for a bounded box (an input, a textarea, a combo). False for a
    # whole document surface, where "select all and delete" would wipe the file.
    bounded: bool = False
    current_value: str = ""
    # What the user has highlighted, and the word sitting just before the
    # caret. Either can become the search word for a double-tap.
    selection: str = ""
    caret_word: str = ""
    rect: Optional[Tuple[int, int, int, int]] = None  # left, top, right, bottom
    texts: List[Tuple[str, str]] = dc_field(default_factory=list)

    @property
    def display_name(self) -> str:
        """The nicest human name we have for this box."""
        for source in ("label", "placeholder", "id", "description", "neighbour"):
            for src, text in self.texts:
                if src == source and text.strip():
                    return " ".join(text.split())[:48]
        return self.control_type or "this field"


def _prop(ctrl, prop_id) -> str:
    try:
        value = ctrl.GetPropertyValue(prop_id)
        return value if isinstance(value, str) else ""
    except Exception:
        return ""


def _value_pattern(ctrl):
    try:
        return ctrl.GetPattern(auto.PatternId.ValuePattern)
    except Exception:
        return None


def _neighbour_label(ctrl) -> str:
    """The static text sitting just before the box — the classic form layout."""
    try:
        parent = ctrl.GetParentControl()
    except Exception:
        return ""
    for _ in range(3):                     # widen the search a couple of levels
        if parent is None:
            return ""
        try:
            children = parent.GetChildren()
        except Exception:
            return ""
        found_self, best = False, ""
        for child in children:
            try:
                same = child.NativeWindowHandle == ctrl.NativeWindowHandle and \
                    child.BoundingRectangle == ctrl.BoundingRectangle
            except Exception:
                same = False
            if same:
                found_self = True
                break
            try:
                if child.ControlType in (auto.ControlType.TextControl,
                                         auto.ControlType.GroupControl) and child.Name:
                    best = child.Name
            except Exception:
                pass
        if found_self and best:
            return best
        try:
            parent = parent.GetParentControl()
        except Exception:
            return ""
    return ""


def _looks_editable(ctrl, class_name: str, vpat) -> bool:
    if any(h in class_name.lower() for h in EDITABLE_CLASS_HINTS):
        return True
    if vpat is not None:
        try:
            if not vpat.IsReadOnly:
                return True
        except Exception:
            return True
    try:
        if ctrl.ControlType in NON_EDITABLE_TYPES:
            return False
    except Exception:
        pass
    return True


def _read_caret(ctrl):
    """(selected text, word before the caret) — either may be empty.

    This is what lets you type "fir", tap twice, and have it become "Alex":
    the word under the caret is the search term, and we know how many
    characters to rub out before typing the answer.
    """
    try:
        pattern = ctrl.GetPattern(auto.PatternId.TextPattern)
    except Exception:
        pattern = None
    if pattern is None:
        return "", ""
    try:
        ranges = pattern.GetSelection()
    except Exception:
        return "", ""
    if not ranges:
        return "", ""

    try:
        caret = ranges[0]
        selected = (caret.GetText(400) or "").strip()
    except Exception:
        return "", ""
    if selected:
        return selected, ""

    # Nothing highlighted: walk the start of the (empty) range back one word.
    try:
        word_range = caret.Clone()
        word_range.MoveEndpointByUnit(auto.TextPatternRangeEndpoint.Start,
                                      auto.TextUnit.Word, -1)
        word = (word_range.GetText(120) or "")
    except Exception:
        return "", ""
    # A word ending in whitespace means the caret is past it, not inside it.
    return "", word.strip() if word[-1:].strip() else ""


def _is_bounded_input(ctrl, class_name: str) -> bool:
    """Is this one box, or a whole document?

    Select-all-then-delete is only ever safe inside a box. In Word, WordPad,
    Notepad or a Chrome contenteditable it would destroy the whole thing, so
    those must come back False.
    """
    if any(h in class_name.lower() for h in DOCUMENT_CLASS_HINTS):
        return False
    try:
        return ctrl.ControlType in (auto.ControlType.EditControl,
                                    auto.ControlType.ComboBoxControl)
    except Exception:
        return False


def inspect_focused(deep: bool = True) -> Optional[FieldContext]:
    """Describe whatever has the keyboard right now, or None if nothing does.

    `deep=False` skips the neighbour-label walk — cheap enough to poll while
    the side panel is on screen.
    """
    try:
        ctrl = auto.GetFocusedControl()
    except Exception:
        ctrl = None
    if ctrl is None:
        return None

    ctx = FieldContext(control=ctrl)
    ctx.hwnd = foreground_window()
    ctx.app = process_name(ctx.hwnd)
    ctx.window_title = window_title(ctx.hwnd)

    try:
        ctx.control_type = ctrl.ControlTypeName.replace("ControlType", "")
    except Exception:
        pass
    try:
        ctx.class_name = ctrl.ClassName or ""
    except Exception:
        pass

    try:
        r = ctrl.BoundingRectangle
        if r and (r.right - r.left) > 0:
            ctx.rect = (r.left, r.top, r.right, r.bottom)
    except Exception:
        pass

    vpat = _value_pattern(ctrl)
    if vpat is not None:
        try:
            ctx.current_value = vpat.Value or ""
        except Exception:
            pass
    ctx.editable = _looks_editable(ctrl, ctx.class_name, vpat)
    ctx.bounded = _is_bounded_input(ctrl, ctx.class_name)
    if deep:
        ctx.selection, ctx.caret_word = _read_caret(ctrl)

    name = ""
    try:
        name = ctrl.Name or ""
    except Exception:
        pass
    automation_id = ""
    try:
        automation_id = ctrl.AutomationId or ""
    except Exception:
        pass

    placeholder = (_prop(ctrl, auto.PropertyId.HelpTextProperty)
                   or _prop(ctrl, auto.PropertyId.FullDescriptionProperty))

    description = ""
    try:
        legacy = ctrl.GetLegacyIAccessiblePattern()
        description = (legacy.Description or "") or (legacy.Help or "")
        if not name:
            name = legacy.Name or ""
    except Exception:
        pass

    # A placeholder often IS the current text of an empty box; do not let the
    # value we are about to overwrite masquerade as a label.
    if placeholder and placeholder == ctx.current_value:
        placeholder = ""

    ctx.texts = [(src, txt) for src, txt in (
        ("label", name),
        ("id", automation_id),
        ("placeholder", placeholder),
        ("description", description),
        ("neighbour", _neighbour_label(ctrl) if deep else ""),
    ) if txt and txt.strip()]

    return ctx


def focus_control(ctx: FieldContext) -> bool:
    """Put the caret back in the box we came from."""
    try:
        ctx.control.SetFocus()
        return True
    except Exception:
        return False


def set_value_directly(ctx: FieldContext, text: str) -> bool:
    """Last-resort fill for boxes that refuse synthetic keystrokes."""
    vpat = _value_pattern(ctx.control)
    if vpat is None:
        return False
    try:
        vpat.SetValue(text)
        return True
    except Exception:
        return False


# ==========================================================================
#  THE ICON
# ==========================================================================
# One shape everywhere: a filled square with a serif T cut out of it, traced
# straight from the supplied SVG on its own 16x16 grid. Only the colour
# changes - green while the buddy is listening, red while it is switched off,
# orange for the program file itself.

ICON_FRAME = [(1, 1), (15, 1), (15, 15), (1, 15)]
ICON_LETTER = [(3, 3), (3, 7), (5, 7), (5, 5), (7, 5), (7, 11), (5, 11),
               (5, 13), (11, 13), (11, 11), (9, 11), (9, 5), (11, 5),
               (11, 7), (13, 7), (13, 3)]

ICON_ON = "#22c55e"        # listening
ICON_OFF = "#ef4444"       # switched off
ICON_FILE = "#f97316"      # the exe on disk


def make_icon(colour: str, size: int = 64):
    """The icon at any size. The letter is punched clean through."""
    scale = size / 16.0
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.polygon([(x * scale, y * scale) for x, y in ICON_FRAME], fill=colour)
    # A plain draw replaces pixels rather than blending, so filling with a
    # fully transparent colour cuts the letter out instead of painting it.
    draw.polygon([(x * scale, y * scale) for x, y in ICON_LETTER],
                 fill=(0, 0, 0, 0))
    return img


# ==========================================================================
#  COLOURS AND FONTS
# ==========================================================================
# One place for the look of every Form Buddy window.

# Three palettes. Every window reads these module-level names when it is
# built, so switching theme means rebuilding the windows - which is exactly
# what set_theme() does.
THEMES = {
    "dark": {
        "BG": "#1c1f26", "BG_ALT": "#23262f", "CARD_BORDER": "#3a3f4b",
        "SELECT": "#2d6cdf", "SELECT_TEXT": "#ffffff", "FG": "#e8eaed",
        "FG_DIM": "#9aa0aa", "FG_FAINT": "#6d737d", "ACCENT": "#4ade80",
        "WARN": "#fbbf24",
    },
    "light": {
        "BG": "#ffffff", "BG_ALT": "#f1f3f6", "CARD_BORDER": "#c9ced8",
        "SELECT": "#2d6cdf", "SELECT_TEXT": "#ffffff", "FG": "#1b1e24",
        "FG_DIM": "#5b6270", "FG_FAINT": "#8b929e", "ACCENT": "#0f8a44",
        "WARN": "#a86400",
    },
    "midnight": {
        "BG": "#000000", "BG_ALT": "#0e1015", "CARD_BORDER": "#2a2f3a",
        "SELECT": "#3b82f6", "SELECT_TEXT": "#ffffff", "FG": "#f5f7fa",
        "FG_DIM": "#9099a8", "FG_FAINT": "#636b78", "ACCENT": "#22d3ee",
        "WARN": "#fbbf24",
    },
}
THEME_LABELS = {"system": "Match Windows", "dark": "Dark",
                "light": "Light", "midnight": "Midnight"}

BG = BG_ALT = CARD_BORDER = SELECT = SELECT_TEXT = ""
FG = FG_DIM = FG_FAINT = ACCENT = WARN = ""


def windows_theme() -> str:
    """Follow Windows: "light" or "dark", falling back to dark."""
    try:
        import winreg
        with winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize"
        ) as key:
            light, _type = winreg.QueryValueEx(key, "AppsUseLightTheme")
        return "light" if light else "dark"
    except Exception:
        return "dark"


def windows_accent() -> str:
    """The accent colour the user picked in Windows, as #rrggbb."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\DWM") as key:
            value, _type = winreg.QueryValueEx(key, "AccentColor")
        # stored as 0xAABBGGRR
        blue = (value >> 16) & 0xFF
        green = (value >> 8) & 0xFF
        red = value & 0xFF
        return "#%02x%02x%02x" % (red, green, blue)
    except Exception:
        return ""


def apply_theme(name: str) -> None:
    """Point the colour names at one of the palettes.

    "system" follows whatever Windows is set to, and borrows the accent
    colour the user picked there, so the app looks like it belongs on the
    desktop rather than like something from another decade.
    """
    if name == "system":
        palette = dict(THEMES[windows_theme()])
        accent = windows_accent()
        if accent:
            palette["SELECT"] = accent
    else:
        palette = dict(THEMES.get(name, THEMES["dark"]))
    globals().update(palette)


apply_theme("system")

def _ui_font() -> str:
    """Windows 11 ships Segoe UI Variable; older builds only have Segoe UI."""
    try:
        from tkinter import font as tkfont
        probe = tk.Tk()
        probe.withdraw()
        families = set(tkfont.families(probe))
        probe.destroy()
        for name in ("Segoe UI Variable Text", "Segoe UI Variable", "Segoe UI"):
            if name in families:
                return name
    except Exception:
        pass
    return "Segoe UI"


UI = _ui_font()
FONT = (UI, 10)
FONT_SMALL = (UI, 9)
FONT_BOLD = (UI, 10, "bold")
FONT_TITLE = (UI, 12, "bold")
FONT_MONO = ("Cascadia Mono", 9)


# ==========================================================================
#  THE LITTLE CONFIRMATION
# ==========================================================================
# A small, silent confirmation near the cursor. Never steals focus.

class Toast:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.win: Optional[tk.Toplevel] = None
        self._after = None

    def _build(self) -> None:
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD_BORDER)
        card = tk.Frame(win, bg=BG_ALT)
        card.pack(padx=1, pady=1, fill="both", expand=True)
        self.icon = tk.Label(card, text="", bg=BG_ALT, fg=ACCENT,
                             font=FONT_BOLD)
        self.icon.pack(side="left", padx=(10, 4), pady=8)
        self.text = tk.Label(card, text="", bg=BG_ALT, fg=FG,
                             font=FONT)
        self.text.pack(side="left", padx=(0, 12), pady=8)
        win.update_idletasks()
        make_non_activating(win.winfo_id())
        self.win = win

    def show(self, message: str, kind: str = "ok", ms: int = 1700,
             rect=None) -> None:
        if self.win is None:
            self._build()
        icon, colour = {
            "ok": ("✓", ACCENT),
            "warn": ("!", WARN),
            "info": ("•", FG_DIM),
        }.get(kind, ("•", FG_DIM))
        self.icon.config(text=icon, fg=colour)
        self.text.config(text=message)

        self.win.update_idletasks()
        w, h = self.win.winfo_reqwidth(), self.win.winfo_reqheight()
        if rect:
            x, y = rect[0], rect[3] + 6
        else:
            cx, cy = cursor_pos()
            x, y = cx + 14, cy + 18
        sw, sh = self.win.winfo_screenwidth(), self.win.winfo_screenheight()
        x = max(8, min(x, sw - w - 8))
        y = max(8, min(y, sh - h - 8))
        self.win.geometry("%dx%d+%d+%d" % (w, h, int(x), int(y)))
        self.win.deiconify()
        self.win.lift()

        if self._after:
            self.root.after_cancel(self._after)
        self._after = self.root.after(ms, self.hide)

    def hide(self) -> None:
        self._after = None
        if self.win is not None:
            self.win.withdraw()


# ==========================================================================
#  THE SEARCH WINDOW
# ==========================================================================
# The one thing a double-tap opens. It sits in the middle of the screen and
# it TAKES focus, so the caret lands in the search box and you just type -
# no borrowed keyboard, no routing keys around behind the scenes.
#
# Whatever box you came from is remembered. Enter puts the answer back there;
# if you came from nowhere in particular, Enter copies it instead.

PALETTE_WIDTH = 620
PALETTE_ROWS = 7
FONT_SEARCH = (UI, 17)
FONT_ROW = (UI, 12)
FONT_ROW_DIM = (UI, 9)


class Palette:
    def __init__(self, root: tk.Tk, app):
        self.root = root
        self.app = app
        self.win = None
        self.is_open = False
        self._rows = []
        self._shown = []
        self._index = 0
        self._all = []

    # -- window ------------------------------------------------------------
    def _build(self) -> None:
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD_BORDER)
        self.win = win

        card = tk.Frame(win, bg=BG)
        card.pack(padx=1, pady=1, fill="both", expand=True)

        top = tk.Frame(card, bg=BG)
        top.pack(fill="x", padx=20, pady=(16, 12))
        tk.Label(top, text="\u2315", bg=BG, fg=FG_FAINT,
                 font=(UI, 19)).pack(side="left", padx=(0, 12))
        self.query = tk.StringVar()
        self.query.trace_add("write", lambda *_a: self._refilter())
        self.entry = tk.Entry(top, textvariable=self.query, bg=BG, fg=FG,
                              insertbackground=ACCENT, relief="flat",
                              font=FONT_SEARCH, highlightthickness=0,
                              borderwidth=0)
        self.entry.pack(side="left", fill="x", expand=True)
        self.where = tk.Label(top, text="", bg=BG, fg=FG_FAINT,
                              font=FONT_ROW_DIM)
        self.where.pack(side="right")
        self.ghost = tk.Label(self.entry, text="Search your answers…",
                              bg=BG, fg=FG_FAINT, font=FONT_SEARCH)

        tk.Frame(card, bg=CARD_BORDER, height=1).pack(fill="x")

        self.body = tk.Frame(card, bg=BG)
        self.body.pack(fill="both", expand=True, padx=8, pady=(8, 8))
        for _ in range(PALETTE_ROWS):
            row = tk.Frame(self.body, bg=BG, height=38)
            row.pack(fill="x", pady=1)
            row.pack_propagate(False)
            label = tk.Label(row, text="", bg=BG, fg=FG, font=FONT_ROW,
                             anchor="w")
            label.pack(side="left", padx=(14, 8))
            value = tk.Label(row, text="", bg=BG, fg=FG_DIM,
                             font=FONT_ROW_DIM, anchor="e")
            value.pack(side="right", padx=(8, 14))
            for widget in (row, label, value):
                widget.bind("<Button-1>", lambda _e, r=len(self._rows):
                            self._click(r))
            self._rows.append((row, label, value))

        self.hint = tk.Label(card, bg=BG_ALT, fg=FG_FAINT, font=FONT_ROW_DIM,
                             text="type to search      \u2191\u2193 move      "
                                  "Enter to use      Esc to close")
        self.hint.pack(fill="x", ipady=6)

        for seq, fn in (("<Escape>", self._cancel), ("<Return>", self._accept),
                        ("<Tab>", self._accept), ("<Up>", self._up),
                        ("<Down>", self._down)):
            self.entry.bind(seq, lambda e, f=fn: (f(), "break")[1])
        win.bind("<FocusOut>", self._focus_out)

    # -- lifecycle ---------------------------------------------------------
    def open(self, ctx, query: str = "", note: str = "") -> None:
        """Show it. `ctx` is the box we came from, or None."""
        if self.win is None:
            self._build()
        self._all = self.app.ordered_answers(ctx)
        self.where.config(text=note or self._describe(ctx))

        self.is_open = True
        self._place()
        self.win.deiconify()
        self.win.lift()
        self.query.set(query)
        self.entry.select_range(0, "end")
        self.entry.icursor("end")
        self._refilter()
        self.win.after(10, self._grab)

    def _grab(self) -> None:
        """Pull the caret into the search box."""
        try:
            self.win.focus_force()
            self.entry.focus_set()
            set_foreground(int(self.win.winfo_id()))
        except Exception:
            pass

    def close(self) -> None:
        self.is_open = False
        if self.win is not None:
            self.win.withdraw()

    def _describe(self, ctx) -> str:
        if ctx is None or not ctx.editable:
            return "no box in front \u2014 Enter copies"
        name = ctx.display_name
        return ("\u2192 %s" % name) if name else "\u2192 back to your form"

    def _place(self) -> None:
        self.win.update_idletasks()
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        height = self.win.winfo_reqheight()
        x = (sw - PALETTE_WIDTH) // 2
        y = max(60, int(sh * 0.22))
        self.win.geometry("%dx%d+%d+%d" % (PALETTE_WIDTH, height, x, y))

    # -- list --------------------------------------------------------------
    def _refilter(self) -> None:
        q = self.query.get().strip()
        if q:
            self.ghost.place_forget()
        else:
            self.ghost.place(x=2, y=0)
        self._shown = search(self._all, q) if q else list(self._all)
        self._index = 0
        self._render()

    def _render(self) -> None:
        if self.win is None:
            return
        visible = self._shown[:PALETTE_ROWS]
        if self._index >= len(visible):
            self._index = max(0, len(visible) - 1)

        for i, (row, label, value) in enumerate(self._rows):
            if i >= len(visible):
                row.pack_forget()
                continue
            row.pack(fill="x", pady=1)
            field = visible[i]
            chosen = (i == self._index)
            bg = SELECT if chosen else BG
            row.config(bg=bg)
            label.config(text=field.label, bg=bg,
                         fg=SELECT_TEXT if chosen else FG)
            value.config(text=field.preview(46), bg=bg,
                         fg=SELECT_TEXT if chosen else FG_DIM)

        if not visible:
            row, label, value = self._rows[0]
            row.pack(fill="x", pady=1)
            row.config(bg=BG)
            label.config(text="Nothing matches that", bg=BG, fg=WARN)
            value.config(text="", bg=BG)

        self.win.update_idletasks()
        self.win.geometry("%dx%d" % (PALETTE_WIDTH, self.win.winfo_reqheight()))

    # -- keys and clicks ---------------------------------------------------
    def _up(self) -> None:
        self._index = max(0, self._index - 1)
        self._render()

    def _down(self) -> None:
        self._index = min(len(self._shown[:PALETTE_ROWS]) - 1, self._index + 1)
        self._render()

    def _click(self, index: int) -> None:
        if index < len(self._shown[:PALETTE_ROWS]):
            self._index = index
            self._accept()

    def _accept(self) -> None:
        visible = self._shown[:PALETTE_ROWS]
        if not visible:
            return self._cancel()
        chosen = visible[self._index]
        self.close()
        self.app.palette_chose(chosen)

    def _cancel(self) -> None:
        self.close()
        self.app.palette_cancelled()

    def _focus_out(self, _event) -> None:
        # Clicking away is the same as pressing Esc.
        if self.is_open:
            self.root.after(80, self._cancel_if_gone)

    def _cancel_if_gone(self) -> None:
        if not self.is_open:
            return
        try:
            if self.win.focus_displayof() is None:
                self._cancel()
        except Exception:
            self._cancel()


# ==========================================================================
#  THE SUGGESTION STRIP
# ==========================================================================
# A thin strip that rises above the taskbar while you are typing a word that
# looks like one of your answers. Hold Alt and use the arrow keys to pick one.
#
# It never takes focus and never types on its own: it only reacts to Alt plus
# an arrow, which nothing else in Windows uses while you are mid-word.

SUGGEST_POLL_MS = 500        # how often the focused box is checked
SUGGEST_MIN_CHARS = 2        # shorter than this and everything matches
SUGGEST_MAX = 5              # chips across the strip
SUGGEST_HEIGHT = 66


class SuggestionBar:
    def __init__(self, root: tk.Tk, app):
        self.root = root
        self.app = app
        self.win = None
        self.visible = False
        self._fields = []
        self._index = 0
        self._word = ""
        self._chips = []

    # -- window ------------------------------------------------------------
    def _build(self) -> None:
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD_BORDER)
        self.win = win

        card = tk.Frame(win, bg=BG_ALT)
        card.pack(padx=1, pady=1, fill="both", expand=True)

        self.word_label = tk.Label(card, text="", bg=BG_ALT, fg=FG_FAINT,
                                   font=FONT_SMALL)
        self.word_label.pack(side="left", padx=(14, 10))

        self.row = tk.Frame(card, bg=BG_ALT)
        self.row.pack(side="left", fill="both", expand=True, pady=5)

        tk.Label(card, text="Alt + \u2190 \u2192  \u00b7  Alt + \u2191 to use",
                 bg=BG_ALT, fg=FG_FAINT, font=FONT_SMALL).pack(side="right",
                                                               padx=14)

        win.update_idletasks()
        make_non_activating(win.winfo_id())

    # -- showing -----------------------------------------------------------
    def show(self, fields, word: str) -> None:
        if self.win is None:
            self._build()
        same = [f.key for f in fields] == [f.key for f in self._fields]
        self._fields = fields[:SUGGEST_MAX]
        self._word = word
        if not same:
            self._index = 0
        self._render()
        if not self.visible:
            self.win.deiconify()
            self.win.lift()
            self.visible = True
            self.app.hook.suggest_visible = True

    def hide(self) -> None:
        if not self.visible:
            return
        self.visible = False
        self.app.hook.suggest_visible = False
        self._fields = []
        self._index = 0
        if self.win is not None:
            self.win.withdraw()

    def _render(self) -> None:
        for chip in self._chips:
            chip.destroy()
        self._chips = []
        self.word_label.config(text="\u201c%s\u201d" % self._word)

        for i, field in enumerate(self._fields):
            chosen = (i == self._index)
            bg = SELECT if chosen else BG
            chip = tk.Frame(self.row, bg=bg, cursor="hand2")
            chip.pack(side="left", padx=4)
            tk.Label(chip, text=field.label, bg=bg,
                     fg=SELECT_TEXT if chosen else FG,
                     font=FONT_BOLD if chosen else FONT).pack(
                         side="top", padx=12, pady=(5, 0))
            tk.Label(chip, text=field.preview(22), bg=bg,
                     fg=SELECT_TEXT if chosen else FG_DIM,
                     font=FONT_SMALL).pack(side="top", padx=12, pady=(0, 5))
            for widget in (chip,) + tuple(chip.winfo_children()):
                widget.bind("<Button-1>", lambda _e, n=i: self._click(n))
            self._chips.append(chip)

        self.win.update_idletasks()
        width = min(self.win.winfo_reqwidth(), work_area()[2] - 80)
        left, _top, right, bottom = work_area()
        x = left + ((right - left) - width) // 2
        y = bottom - SUGGEST_HEIGHT - 10
        self.win.geometry("%dx%d+%d+%d" % (width, SUGGEST_HEIGHT, x, y))

    # -- keys, fed by the global hook --------------------------------------
    def move(self, step: int) -> None:
        if not self.visible or not self._fields:
            return
        self._index = (self._index + step) % len(self._fields)
        self._render()

    def choose(self) -> None:
        if not self.visible or not self._fields:
            return
        field = self._fields[self._index]
        word = self._word
        self.hide()
        self.app.fill_from_suggestion(field, word)

    def _click(self, index: int) -> None:
        self._index = index
        self.choose()


# ==========================================================================
#  THE SIDE DOCK
# ==========================================================================
# The dock: a slim panel that hides at the edge of the screen.
# 
# It stays out of the way. A thin handle sits on the screen edge; touch it with
# the mouse and the panel opens. Move the mouse away and it closes again.
# 
# A double-tap on a word you typed also opens it, filtered to what you typed,
# and then waits — it will not close until you have been over it and left, so
# you always get a chance to click.
# 
# Like every other overlay it never takes focus, so the box you clicked in Word,
# Excel or a web form keeps the caret.

PANEL_WIDTH = 300
HANDLE_WIDTH = 6
HANDLE_HEIGHT = 190          # roughly two inches at 96 dpi
CURSOR_POLL_MS = 110
FIELD_POLL_MS = 600
LONG_PRESS_MS = 550


class Panel:
    def __init__(self, root: tk.Tk, app):
        self.root = root
        self.app = app
        self.win: Optional[tk.Toplevel] = None
        self.handle: Optional[tk.Toplevel] = None
        self.visible = False

        self._rows = []
        self._query = ""
        self._editing = False          # the long-press value editor is open
        self._ctx = None
        self._ctx_key = None

        # Set when a double-tap opened us: wait for the mouse to arrive before
        # arming the leave-to-close behaviour.
        self._awaiting_visit = False
        self._left_at = None
        self._cursor_job = None
        self._field_job = None
        self._press_job = None
        self._menu = None

    # -- windows ---------------------------------------------------------
    def _build(self) -> None:
        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD_BORDER)
        self.win = win

        card = tk.Frame(win, bg=BG)
        card.pack(padx=1, pady=1, fill="both", expand=True)

        head = tk.Frame(card, bg=BG_ALT)
        head.pack(fill="x")
        title = tk.Frame(head, bg=BG_ALT)
        title.pack(fill="x", padx=10, pady=(8, 2))
        self.who = tk.Label(title, text="Form Buddy", bg=BG_ALT, fg=FG,
                            font=FONT_TITLE)
        self.who.pack(side="left")
        for glyph, action in (("✕", self.hide), ("⇄", self.flip_side),
                              ("⋯", self.open_menu)):
            btn = tk.Label(title, text=glyph, bg=BG_ALT, fg=FG_FAINT,
                           font=FONT_BOLD, cursor="hand2")
            btn.pack(side="right", padx=(0, 0 if glyph == "✕" else 10))
            btn.bind("<Button-1>", lambda _e, a=action: a())

        self.detected = tk.Label(head, text="", bg=BG_ALT, fg=FG_DIM,
                                 font=FONT_SMALL, anchor="w",
                                 wraplength=PANEL_WIDTH - 24, justify="left")
        self.detected.pack(fill="x", padx=10, pady=(0, 8))

        self.search = tk.Label(card, text="", bg=BG_ALT, fg=FG_FAINT,
                               font=FONT, anchor="w", cursor="hand2")
        self.search.pack(fill="x", padx=8, pady=(8, 4), ipady=5, ipadx=8)
        self.search.bind("<Button-1>", lambda _e: self.open_search())

        holder = tk.Frame(card, bg=BG)
        holder.pack(fill="both", expand=True, padx=4, pady=(0, 4))
        self.canvas = tk.Canvas(holder, bg=BG, highlightthickness=0,
                                width=PANEL_WIDTH - 12)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.list_frame = tk.Frame(self.canvas, bg=BG)
        self._window_id = self.canvas.create_window(
            (0, 0), window=self.list_frame, anchor="nw")
        self.list_frame.bind(
            "<Configure>",
            lambda _e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfig(self._window_id, width=e.width))
        for widget in (self.canvas, self.list_frame):
            widget.bind("<MouseWheel>", self._on_wheel)

        self.hint = tk.Label(card, bg=BG_ALT, fg=FG_FAINT,
                             font=FONT_SMALL, text="")
        self.hint.pack(fill="x", ipady=5)

        win.update_idletasks()
        make_non_activating(win.winfo_id())
        win.withdraw()

    def _build_handle(self) -> None:
        """The sliver on the screen edge that opens the panel on hover."""
        handle = tk.Toplevel(self.root)
        handle.overrideredirect(True)
        handle.attributes("-topmost", True)
        handle.configure(bg=SELECT)
        handle.update_idletasks()
        make_non_activating(handle.winfo_id())
        self.handle = handle
        self._place_handle()

    def _place_handle(self) -> None:
        if self.handle is None:
            return
        sw = self.handle.winfo_screenwidth()
        sh = self.handle.winfo_screenheight()
        x = 0 if self._side() == "left" else sw - HANDLE_WIDTH
        y = max(0, (sh - HANDLE_HEIGHT) // 2)
        self.handle.geometry("%dx%d+%d+%d" % (HANDLE_WIDTH, HANDLE_HEIGHT, x, y))
        self.handle.deiconify()
        self.handle.lift()

    def _side(self) -> str:
        return self.app.settings.get("panel_side", "left")

    def _on_wheel(self, event) -> None:
        self.canvas.yview_scroll(int(-event.delta / 120), "units")

    # -- lifecycle -------------------------------------------------------
    def start(self) -> None:
        """Put the handle on screen and begin watching the cursor."""
        if self.win is None:
            self._build()
        if self.handle is None:
            self._build_handle()
        self._watch_cursor()

    def toggle(self) -> None:
        self.hide() if self.visible else self.show()

    def show(self, awaiting_visit: bool = False) -> None:
        if self.win is None:
            self._build()
        self._awaiting_visit = awaiting_visit
        self._left_at = None
        self._rebuild_rows()
        self._place()
        self.win.deiconify()
        self.win.lift()
        self.visible = True
        if self.handle is not None:
            self.handle.withdraw()
        self._watch_field()

    def hide(self) -> None:
        self.close_menu()
        self.visible = False
        self._awaiting_visit = False
        self._query = ""
        if self._field_job:
            self.root.after_cancel(self._field_job)
            self._field_job = None
        if self.win is not None:
            self.win.withdraw()
        if self.handle is not None:
            self._place_handle()

    def flip_side(self) -> None:
        self.app.settings["panel_side"] = \
            "right" if self._side() == "left" else "left"
        self.app.save_settings()
        self._place()
        self._place_handle()

    def _place(self) -> None:
        if self.win is None:
            return
        sw = self.win.winfo_screenwidth()
        sh = self.win.winfo_screenheight()
        height = max(360, sh - 120)
        x = 0 if self._side() == "left" else sw - PANEL_WIDTH
        self.win.geometry("%dx%d+%d+%d" % (PANEL_WIDTH, height, x, 40))

    # -- opening and closing by mouse ------------------------------------
    def _rect(self):
        if self.win is None or not self.visible:
            return None
        return (self.win.winfo_rootx(), self.win.winfo_rooty(),
                self.win.winfo_rootx() + self.win.winfo_width(),
                self.win.winfo_rooty() + self.win.winfo_height())

    def _over_handle(self, x, y) -> bool:
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        top = max(0, (sh - HANDLE_HEIGHT) // 2)
        if not (top <= y <= top + HANDLE_HEIGHT):
            return False
        return x <= HANDLE_WIDTH if self._side() == "left" \
            else x >= sw - HANDLE_WIDTH

    def _watch_cursor(self) -> None:
        """Cheap poll: open on the edge, close once the mouse wanders off."""
        try:
            x, y = cursor_pos()
            if not self.visible:
                if self.app.enabled and self._over_handle(x, y):
                    self.show()
            elif not (self._editing or self._menu):
                rect = self._rect()
                inside = rect and rect[0] <= x <= rect[2] and rect[1] <= y <= rect[3]
                if inside:
                    self._awaiting_visit = False
                    self._left_at = None
                elif not self._awaiting_visit:
                    now = self.root.tk.call("clock", "milliseconds")
                    if self._left_at is None:
                        self._left_at = now
                    elif now - self._left_at >= self.app.settings.get(
                            "panel_hide_delay_ms", 800):
                        self.hide()
        except Exception:
            pass
        self._cursor_job = self.root.after(CURSOR_POLL_MS, self._watch_cursor)

    # -- live field detection --------------------------------------------
    def _watch_field(self) -> None:
        if not self.visible:
            return
        if not (self._query or self._editing):
            try:
                ctx = self.app.inspect_target(deep=False)
            except Exception:
                ctx = None
            key = tuple(ctx.texts) if ctx else None
            if key != self._ctx_key:
                self._ctx_key, self._ctx = key, ctx
                self._rebuild_rows()
        self._field_job = self.root.after(FIELD_POLL_MS, self._watch_field)

    def refresh(self) -> None:
        if self.visible:
            self._ctx_key = None
            self._rebuild_rows()

    # -- opened by a double-tap on a typed word ---------------------------
    # -- rows -------------------------------------------------------------
    def _ordered_fields(self) -> List:
        answers = self.app.profile.filled()
        if self._query:
            return search(answers, self._query)
        if self._ctx and self._ctx.texts:
            best = [f for f, _s, _t in rank(answers, self._ctx.texts)]
            return best + [f for f in answers if f not in best]
        return answers

    def _rebuild_rows(self) -> None:
        if self.win is None:
            return
        self.who.config(text=SESSION.username or "Form Buddy")
        for row in self._rows:
            row.destroy()
        self._rows = []

        if self._query:
            self.detected.config(text="replacing “%s”" % self._query[:30],
                                 fg=WARN)
        elif self._ctx and self._ctx.editable and self._ctx.texts:
            self.detected.config(
                text="in “%s” — %s" % (self._ctx.display_name,
                                       self._ctx.app or "app"), fg=ACCENT)
        elif self._ctx and self._ctx.editable:
            self.detected.config(text="ready — %s" % (self._ctx.app or "app"),
                                 fg=FG_DIM)
        else:
            self.detected.config(text="click into a box on your form",
                                 fg=FG_FAINT)

        self.search.config(
            text=("search: " + self._query) if self._query
            else "🔍  click here to search",
            fg=ACCENT if (self._query) else FG_FAINT)

        self.hint.config(
            text="click an answer · hold one to edit it")

        fields = self._ordered_fields()
        highlight_first = bool(self._ctx and self._ctx.texts) or bool(self._query)
        for i, f in enumerate(fields):
            self._rows.append(self._make_row(f, highlight_first and i == 0))

        if not fields:
            empty = tk.Label(self.list_frame,
                             text="Nothing matches that." if self._query
                             else "No answers yet.\nTray icon → Edit answers.",
                             bg=BG, fg=WARN, font=FONT_SMALL,
                             justify="left")
            empty.pack(fill="x", padx=10, pady=12)
            self._rows.append(empty)

        self.canvas.yview_moveto(0)

    def _make_row(self, f, highlight: bool) -> tk.Frame:
        bg = BG_ALT if highlight else BG
        row = tk.Frame(self.list_frame, bg=bg, cursor="hand2")
        row.pack(fill="x", pady=(0, 1), padx=2)
        label = tk.Label(row, text=f.label, bg=bg,
                         fg=ACCENT if highlight else FG,
                         font=FONT_BOLD if highlight else FONT,
                         anchor="w")
        label.pack(fill="x", padx=8, pady=(4, 0))
        value = tk.Label(row, text=f.preview(38), bg=bg, fg=FG_DIM,
                         font=FONT_SMALL, anchor="w")
        value.pack(fill="x", padx=8, pady=(0, 4))

        widgets = (row, label, value)
        for w in widgets:
            w.bind("<ButtonPress-1>", lambda _e, fld=f: self._press(fld))
            w.bind("<ButtonRelease-1>", lambda _e, fld=f: self._release(fld))
            w.bind("<MouseWheel>", self._on_wheel)
            w.bind("<Enter>", lambda _e, ws=widgets: self._hover(ws, True, highlight))
            w.bind("<Leave>", lambda _e, ws=widgets: self._hover(ws, False, highlight))
        return row

    def _hover(self, widgets, on: bool, highlight: bool) -> None:
        bg = SELECT if on else (BG_ALT if highlight else BG)
        for w in widgets:
            try:
                w.config(bg=bg)
            except tk.TclError:
                pass

    # -- click vs long press ----------------------------------------------
    def _press(self, f) -> None:
        self._cancel_press()
        self._press_job = self.root.after(LONG_PRESS_MS,
                                          lambda: self._begin_edit(f))

    def _release(self, f) -> None:
        if self._press_job is None:
            return                       # the long press already fired
        self._cancel_press()
        self._choose(f)

    def _cancel_press(self) -> None:
        if self._press_job is not None:
            self.root.after_cancel(self._press_job)
            self._press_job = None

    def _choose(self, f) -> None:
        self.app.fill_from_panel(f)
        self.hide()

    # -- long press: edit the value in place -------------------------------
    def _begin_edit(self, f) -> None:
        self._press_job = None
        self._editing = True

        dialog = tk.Toplevel(self.root)
        dialog.title("Edit " + f.label)
        dialog.configure(bg=BG)
        dialog.attributes("-topmost", True)
        dialog.resizable(False, False)
        tk.Label(dialog, text=f.label, bg=BG, fg=FG,
                 font=FONT_BOLD).pack(padx=16, pady=(14, 6), anchor="w")
        var = tk.StringVar(value=f.value)
        entry = tk.Entry(dialog, textvariable=var, bg=BG_ALT, fg=FG,
                         insertbackground=FG, relief="flat", width=46,
                         font=FONT)
        entry.pack(padx=16, ipady=5)
        entry.selection_range(0, "end")

        bar = tk.Frame(dialog, bg=BG)
        bar.pack(fill="x", padx=16, pady=14)

        def finish(save):
            self._editing = False
            if save:
                f.value = var.get()
                self.app.profile.save()
                self.app.on_profile_changed()
            dialog.destroy()
            self._rebuild_rows()

        tk.Button(bar, text="Save", width=10, relief="flat", bg=SELECT,
                  fg=SELECT_TEXT,
                  command=lambda: finish(True)).pack(side="right")
        tk.Button(bar, text="Cancel", width=10, relief="flat", bg=BG_ALT,
                  fg=FG,
                  command=lambda: finish(False)).pack(side="right", padx=(0, 8))
        dialog.bind("<Return>", lambda _e: finish(True))
        dialog.bind("<Escape>", lambda _e: finish(False))
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(False))

        dialog.update_idletasks()
        x, y = cursor_pos()
        dialog.geometry("+%d+%d" % (min(x + 12, dialog.winfo_screenwidth() - 400),
                                    min(y, dialog.winfo_screenheight() - 180)))
        dialog.lift()
        dialog.focus_force()
        entry.focus_set()

    def open_search(self) -> None:
        """The sidebar's search bar hands over to the real search window."""
        self.hide()
        self.app.post("search")

    # -- the menu behind the three dots -------------------------------------
    def open_menu(self) -> None:
        """Everything that is not filling in a form lives behind one button."""
        if self._menu is not None and self._menu.winfo_exists():
            return self.close_menu()

        win = tk.Toplevel(self.root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.configure(bg=CARD_BORDER)
        self._menu = win
        body = tk.Frame(win, bg=BG_ALT)
        body.pack(padx=1, pady=1, fill="both", expand=True)

        items = (
            ("\uff0b   Add an answer", self._menu_add),
            ("\u270e   Answers", lambda: self.app.post("editor")),
            ("\u2699   Settings", lambda: self.app.post("settings")),
            ("?   Help", lambda: self.app.post("help")),
            ("\u2139   About", lambda: self.app.post("about")),
            None,
            ("\u2193   Import answers", self._menu_import),
            ("\u2191   Export answers", self._menu_export),
            ("\u27f3   Reload answers", lambda: self.app.post("reload")),
            None,
            ("\u21c4   Move to the other side", self.flip_side),
            (lambda: ("\u25cf   Listening for %s" % self.app.hotkey_label)
             if self.app.enabled else "\u25cb   Not listening",
             lambda: self.app.post("toggle")),
            None,
            ("\U0001f512   Lock / switch person", lambda: self.app.post("lock")),
            ("\u2715   Quit Form Buddy", lambda: self.app.post("quit")),
        )
        for item in items:
            if item is None:
                tk.Frame(body, bg=CARD_BORDER, height=1).pack(fill="x", pady=4)
                continue
            text, action = item
            row = tk.Label(body, text=text() if callable(text) else text,
                           bg=BG_ALT, fg=FG, font=FONT,
                           anchor="w", cursor="hand2", padx=14, pady=7)
            row.pack(fill="x")
            row.bind("<Button-1>",
                     lambda _e, a=action: (self.close_menu(), a()))
            row.bind("<Enter>",
                     lambda e: e.widget.config(bg=SELECT, fg=SELECT_TEXT))
            row.bind("<Leave>", lambda e: e.widget.config(bg=BG_ALT, fg=FG))

        tk.Label(body, bg=BG, fg=FG_FAINT, font=FONT_SMALL, justify="left",
                 anchor="w", padx=14, pady=7, wraplength=PANEL_WIDTH - 40,
                 text="Quick add: type  fm=last name=Perera  in any box, "
                      "then tap %s" % self.app.hotkey_label).pack(fill="x")

        win.update_idletasks()
        make_non_activating(win.winfo_id())
        x = self.win.winfo_rootx() + (
            8 if self._side() == "left"
            else PANEL_WIDTH - win.winfo_reqwidth() - 8)
        win.geometry("+%d+%d" % (x, self.win.winfo_rooty() + 62))
        win.lift()

    def close_menu(self) -> None:
        if self._menu is not None:
            try:
                self._menu.destroy()
            except tk.TclError:
                pass
            self._menu = None

    def _menu_export(self) -> None:
        message = export_profile(self.root, self.app.profile)
        if message:
            self.app.toast.show(message, "ok")

    def _menu_import(self) -> None:
        message = import_profile(self.root, self.app.profile)
        if message:
            self.app.on_profile_changed()
            self.app.toast.show(message, "ok")

    def _menu_add(self) -> None:
        """Two boxes: what to call it, and what the answer is."""
        self._editing = True
        dialog = tk.Toplevel(self.root)
        dialog.title("Add an answer")
        dialog.configure(bg=BG)
        dialog.attributes("-topmost", True)
        dialog.resizable(False, False)

        name, value = tk.StringVar(), tk.StringVar()
        first = None
        for caption, var in (("What should this be called?", name),
                             ("The answer", value)):
            tk.Label(dialog, text=caption, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                     anchor="w").pack(fill="x", padx=16, pady=(12, 2))
            entry = tk.Entry(dialog, textvariable=var, bg=BG_ALT, fg=FG,
                             insertbackground=FG, relief="flat", width=42,
                             font=FONT)
            entry.pack(padx=16, ipady=5)
            first = first or entry

        def finish(save):
            self._editing = False
            if save and name.get().strip() and value.get().strip():
                self.app.add_answer(name.get().strip(), value.get().strip())
            dialog.destroy()
            self._rebuild_rows()

        bar = tk.Frame(dialog, bg=BG)
        bar.pack(fill="x", padx=16, pady=14)
        tk.Button(bar, text="Add", width=10, relief="flat", bg=SELECT,
                  fg=SELECT_TEXT,
                  command=lambda: finish(True)).pack(side="right")
        tk.Button(bar, text="Cancel", width=10, relief="flat", bg=BG_ALT,
                  fg=FG,
                  command=lambda: finish(False)).pack(side="right", padx=(0, 8))
        dialog.bind("<Return>", lambda _e: finish(True))
        dialog.bind("<Escape>", lambda _e: finish(False))
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(False))
        dialog.update_idletasks()
        dialog.geometry("+%d+%d"
                        % (self.win.winfo_rootx() + PANEL_WIDTH + 20, 160))
        dialog.lift()
        dialog.focus_force()
        if first is not None:
            first.focus_set()

    # -- search (keyboard borrowed from the app underneath) ---------------


def export_profile(parent, profile) -> str:
    """Write every answer to a file the user picks. Returns a status line."""
    path = filedialog.asksaveasfilename(
        parent=parent, title="Export your answers", defaultextension=".json",
        initialfile="form-buddy-answers.json",
        filetypes=[("Form Buddy answers", "*.json"), ("All files", "*.*")])
    if not path:
        return ""
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump({"fields": [f.to_dict() for f in profile.fields]},
                      fh, indent=2)
    except OSError as exc:
        messagebox.showerror("Form Buddy", "Could not write that file:\n%s" % exc,
                             parent=parent)
        return ""
    return "Exported %d answers." % len(profile.filled())


def import_profile(parent, profile) -> str:
    """Read answers back in.

    Only non-empty values are taken, so importing tops a profile up rather
    than blanking the answers already in it.
    """
    path = filedialog.askopenfilename(
        parent=parent, title="Import answers",
        filetypes=[("Form Buddy answers", "*.json"), ("All files", "*.*")])
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            entries = json.load(fh)["fields"]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        messagebox.showerror("Form Buddy",
                             "That does not look like an answers file:\n%s" % exc,
                             parent=parent)
        return ""
    if not messagebox.askyesno(
            "Form Buddy",
            "Import %d answers?\n\nAnything with a value will overwrite the "
            "matching answer here. Blank ones are ignored." % len(entries),
            parent=parent):
        return ""

    added = updated = 0
    for entry in entries:
        if not (entry.get("value") or "").strip():
            continue
        existing = profile.get(entry.get("key", ""))
        if existing is None:
            profile.fields.append(Field.from_dict(entry))
            added += 1
        else:
            existing.value = entry["value"]
            updated += 1
    profile.save()
    return "Imported %d answers (%d new)." % (updated + added, added)


# ==========================================================================
#  THE LOCK SCREEN
# ==========================================================================
# The first thing you see. It lists who has a vault on this machine - that
# much is readable from the file names alone - and asks for a password.
#
# Nothing here is checked against a stored password, because there isn't one.
# The password becomes a key; either the key opens the vault or it doesn't.


class Login:
    """Sign in, or set up a new person. Blocks until one or the other."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.result = None          # (username, key) once someone gets in
        self.win = None
        self.mode = "unlock"        # unlock | create
        self.moved = 0              # answers carried in from an older install

    def run(self):
        """Show it and wait. Returns (username, key), or None if they gave up."""
        self.win = tk.Toplevel(self.root)
        win = self.win
        win.title("Form Buddy")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.protocol("WM_DELETE_WINDOW", self._give_up)

        self.body = tk.Frame(win, bg=BG)
        self.body.pack(fill="both", expand=True)
        self.mode = "unlock" if list_users() else "create"
        self._render()

        win.update_idletasks()
        w, h = win.winfo_width(), win.winfo_height()
        win.geometry("+%d+%d" % ((win.winfo_screenwidth() - w) // 2,
                                 max(60, (win.winfo_screenheight() - h) // 3)))
        # Launched from a shortcut we may have no claim on the foreground, so
        # insist: topmost for a moment, then drop back to a normal window.
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        set_foreground(int(win.winfo_id()))
        win.after(600, lambda: win.attributes("-topmost", False))
        win.grab_set()
        self.root.wait_window(win)
        return self.result

    # -- drawing -----------------------------------------------------------
    def _render(self) -> None:
        for child in self.body.winfo_children():
            child.destroy()
        (self._draw_unlock if self.mode == "unlock" else self._draw_create)()

    def _legacy_count(self) -> int:
        """How many answers are sitting in the old unencrypted file, if any."""
        try:
            with open(LEGACY_PROFILE, "r", encoding="utf-8") as fh:
                fields = json.load(fh).get("fields", [])
            return len([f for f in fields if (f.get("value") or "").strip()])
        except (OSError, ValueError, AttributeError):
            return 0

    def _title(self, text, sub) -> None:
        tk.Label(self.body, text=text, bg=BG, fg=FG, font=(UI, 15, "bold"),
                 anchor="w").pack(fill="x", padx=26, pady=(22, 2))
        tk.Label(self.body, text=sub, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w", justify="left", wraplength=360).pack(
                     fill="x", padx=26, pady=(0, 14))

    def _field(self, caption, show=None):
        tk.Label(self.body, text=caption, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w").pack(fill="x", padx=26, pady=(8, 2))
        var = tk.StringVar()
        entry = tk.Entry(self.body, textvariable=var, bg=BG_ALT, fg=FG,
                         insertbackground=FG, relief="flat", font=FONT,
                         width=34, show=show)
        entry.pack(padx=26, ipady=6)
        return var, entry

    def _status(self) -> None:
        self.status = tk.Label(self.body, text="", bg=BG, fg=WARN,
                               font=FONT_SMALL, anchor="w", wraplength=360,
                               justify="left")
        self.status.pack(fill="x", padx=26, pady=(10, 0))

    def _buttons(self, primary_text, primary, secondary_text, secondary) -> None:
        bar = tk.Frame(self.body, bg=BG)
        bar.pack(fill="x", padx=26, pady=(16, 22))
        tk.Button(bar, text=primary_text, command=primary, width=14,
                  relief="flat", bg=SELECT, fg=SELECT_TEXT,
                  activebackground=SELECT,
                  activeforeground=SELECT_TEXT).pack(side="right")
        if secondary_text:
            tk.Button(bar, text=secondary_text, command=secondary, width=14,
                      relief="flat", bg=BG_ALT, fg=FG,
                      activebackground=CARD_BORDER).pack(side="right",
                                                         padx=(0, 8))

    # -- unlock ------------------------------------------------------------
    def _draw_unlock(self) -> None:
        users = list_users()
        self._title("Unlock your answers",
                    "Everything is encrypted with your password. It is not "
                    "stored anywhere, so there is nothing to reset and "
                    "nothing to recover if you lose it.")

        tk.Label(self.body, text="Who are you?", bg=BG, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x", padx=26, pady=(4, 2))
        self.user = tk.StringVar(value=users[0])
        picker = ttk.Combobox(self.body, textvariable=self.user, values=users,
                              state="readonly", width=32, font=FONT)
        picker.pack(padx=26)

        self.password, entry = self._field("Password", show="\u2022")
        self._status()
        self._buttons("Unlock", self._unlock, "New person", self._to_create)
        entry.bind("<Return>", lambda _e: self._unlock())
        self.body.after(60, entry.focus_set)

    def _unlock(self) -> None:
        name = self.user.get().strip()
        try:
            payload, key = read_vault(name, self.password.get())
        except WrongPassword as exc:
            self.status.config(text=str(exc).capitalize() + ".")
            return
        except VaultMissing:
            self.status.config(text="There is no vault for %s any more." % name)
            return
        self.result = (name, key, payload)
        self.win.destroy()

    # -- create ------------------------------------------------------------
    def _to_create(self) -> None:
        self.mode = "create"
        self._render()

    def _to_unlock(self) -> None:
        self.mode = "unlock"
        self._render()

    def _draw_create(self) -> None:
        first = not list_users()
        blurb = ("Choose a name and a password. The password is never written "
                 "down anywhere — it only ever becomes the key that "
                 "unlocks your file, so nobody, including this app, can "
                 "recover it if you forget it.")
        waiting = self._legacy_count()
        if waiting:
            blurb += ("\n\nThe %d answers already on this machine will be "
                      "moved in and encrypted, and the old unprotected file "
                      "set aside." % waiting)
        self._title("Protect your answers" if first else "Add another person",
                    blurb)
        self.newname, entry = self._field("Name (this becomes the file name)")
        self.password, _p1 = self._field("Password", show="\u2022")
        self.confirm, p2 = self._field("Password again", show="\u2022")
        self._status()
        self._buttons("Create", self._create,
                      None if first else "Back", self._to_unlock)
        p2.bind("<Return>", lambda _e: self._create())
        self.body.after(60, entry.focus_set)

    def _create(self) -> None:
        name = self.newname.get().strip()
        pw = self.password.get()
        if not valid_username(name):
            self.status.config(text="Use letters, digits, spaces, dots, "
                                    "dashes or underscores - it has to work "
                                    "as a file name.")
            return
        if vault_path(name).exists():
            self.status.config(text="%s already has a vault here." % name)
            return
        if len(pw) < 6:
            self.status.config(text="Use at least 6 characters.")
            return
        if pw != self.confirm.get():
            self.status.config(text="Those two passwords are not the same.")
            return

        payload = {"fields": []}
        note = ""
        if LEGACY_PROFILE.exists():
            # An older, unencrypted profile is sitting there. Bring it in.
            try:
                with open(LEGACY_PROFILE, "r", encoding="utf-8") as fh:
                    payload = json.load(fh)
                note = " and brought your existing answers in"
            except (OSError, ValueError):
                payload = {"fields": []}

        key = create_vault(name, pw, payload)

        # Read it straight back with the password before trusting any of it.
        # A vault that says it took your answers but did not is the one
        # failure here that must never pass quietly.
        wanted = _count_answers(payload)
        try:
            check, _k = read_vault(name, pw)
            landed = _count_answers(check)
        except Exception as exc:
            self.status.config(text="The vault would not open after being "
                                    "written (%s). Nothing was moved." % exc)
            return
        if landed != wanted:
            self.status.config(
                text="Only %d of %d answers made it into the vault, so your "
                     "old file has been left exactly where it was."
                     % (landed, wanted))
            return

        self.result = (name, key, check)
        if wanted:
            # Safe to set the old copy aside now, and only now.
            keep = LEGACY_PROFILE.with_name("profile.pre-encryption.json")
            try:
                os.replace(LEGACY_PROFILE, keep)
            except OSError:
                pass
        self.moved = wanted
        self.win.destroy()

    def _give_up(self) -> None:
        self.result = None
        self.win.destroy()


HELP_TEXT = """HOW FORM BUDDY WORKS

Form Buddy keeps your usual answers - name, email, phone, address and so on -
and types them into forms for you. It works in web forms, Word, Excel, PDF
form fields, desktop dialogs, anywhere Windows lets it read a text box.

Everything happens through one shortcut and one window.


1. THE SHORTCUT

Click into a box, then tap Alt twice, quickly. A search window opens in the
middle of the screen with the cursor already in it. Type, press Enter, done.

   Example
     You are on a job application. Click the "Email" box.
     Tap Alt Alt. The window opens with Email at the top.
     Press Enter. Your email is typed into the box.

If you were not in a text box at all, Enter copies the answer to the
clipboard instead, so you can paste it wherever you like.


2. TYPE A FEW LETTERS FIRST, AND IT SKIPS THE WINDOW

If you type part of what you want before tapping, Form Buddy searches for it.
When exactly one answer matches, it fills straight in with no window at all.

   Example - one match, no window
     Type:   ema
     Tap:    Alt Alt
     Result: "ema" is replaced with your email address.

   Example - several matches
     Type:   ref
     Tap:    Alt Alt
     "ref" matches Reference 1 name, Reference 1 email and Reference 2 name,
     so the window opens already searching "ref". Pick one with the arrow
     keys and press Enter. Your typed "ref" is swapped for the answer.


3. HIGHLIGHT SOMETHING TO REPLACE JUST THAT

Select some text, tap Alt Alt, and only the highlighted part changes. The
rest of the box is left alone.

   Example
     The box reads:  Dear Sir, I am NAME and I need help
     Highlight:      NAME
     Tap:            Alt Alt, choose Full name
     Result:         Dear Sir, I am Alex Perera and I need help


4. FILL A WHOLE LETTER AT ONCE

Write fb= followed by the name of an answer wherever you want one dropped in.
Then tap Alt Alt once, anywhere in that box, and every placeholder is filled
one after another, top to bottom.

   Example
     Type this into Word, an email, or any big text box:

       Dear Sir, my name is fb=last name and you can reach me
       at fb=email. Please call fb=phone if needed.
       Regards, fb=first name

     Tap Alt Alt once. It becomes:

       Dear Sir, my name is Perera and you can reach me
       at your.address@example.com. Please call +94 77 000 0000 if needed.
       Regards, Alex

   If one of the names is ambiguous - fb=reference, say, when you have three
   of them - it stops there, opens the search window for that one, and
   carries on by itself once you pick.

   Only the words that actually name an answer are used, so
   "fb=last name and thanks" fills in the last name and leaves "and thanks"
   exactly where it is.


5. ADD AN ANSWER WITHOUT OPENING ANYTHING

Type fm= then what to call it, = then the answer, and tap Alt Alt.

   Example
     Type:   fm=nickname=Vi
     Tap:    Alt Alt
     Result: "Nickname" is saved, and the line you typed is cleared out of
             the box again so nothing is left behind.

   If you already have an answer by that name it is updated, not duplicated.
   Anything added this way lands in Uncategorised, so you can file it later
   rather than being asked in the middle of what you were doing.

   fb= and fm= both work for both jobs. What tells them apart is the second
   "=": two parts means save it, one part means fill it in.


6. THE SUGGESTION STRIP

While you type, a slim strip rises above the taskbar showing any of your
answers that match the word you are part-way through. Hold Alt and use the
arrow keys to take one, without reaching for the mouse or the search window.

   Example
     Start typing:  ema
     The strip shows: Email, and anything else that matches.
     Hold Alt, press the up arrow. "ema" becomes your email address.

     Alt + left / right   move along the strip
     Alt + up             use the highlighted one

It only appears once you have typed two letters or more, only when something
matches, and never while a Form Buddy window is open. Turn it off in Settings
if you would rather not have it.


7. THE SIDEBAR

A thin strip sits on the edge of your screen. Touch it with the mouse and the
sidebar slides open; move away and it hides again.

   Clicking an answer in the sidebar COPIES it to the clipboard. It never
   types into your form. That way a stray click can never overwrite what you
   are working on - only Alt Alt writes.

   Press and hold an answer for half a second to edit its value on the spot.

   The three dots open every other option: add an answer, the Answers,
   Settings, Help and About windows, import, export, reload, which side the
   sidebar sits on, whether it is listening, lock or switch person, and quit.


8. THE ANSWERS WINDOW

Search at the top, everything grouped by category underneath.

   Search matches labels, categories, other names for a field, and values,
   so typing "colombo" finds your City.

   Each row has the value, a category dropdown, and an X to remove it.
   Removing an answer you invented deletes it. Removing a built-in one only
   empties it, so it is there ready next time.

   Pick "New category..." in any dropdown to invent a group of your own.

   Answers, Settings, Help and About are separate windows, and only one is
   ever open: opening Settings puts Answers away rather than stacking on it.


9. WHEN IT GUESSES WRONG

With nothing typed, the search window opens with its best guess for that box
at the top - it reads the box's own label, its id, its placeholder and the
text next to it. If the guess is wrong, just keep typing to search, or use
the arrow keys.


10. YOUR ANSWERS ARE ENCRYPTED

Each person has their own file, locked with their own password:

   %APPDATA%\\FormBuddy\\users\\<name>.fbvault

The password is never stored anywhere - not written down, not hashed, not
remembered. It is turned into a key, the key opens the file, and that is all.
Nobody can recover it for you if you forget it, including this app.

Use Lock / switch person in the sidebar menu to sign out or change person.


11. THE ICON

The same shape everywhere, and the colour tells you the state.

   Green    running and listening for the shortcut
   Red      switched off
   Orange   the program file itself, FormBuddy.exe


12. IF SOMETHING IS NOT WORKING

  * Nothing happens on Alt Alt
      Check the sidebar menu says "Listening". Some windows run as
      administrator and will ignore a normal program's keystrokes - run Form
      Buddy as administrator too if you need it there.

  * A menu bar flashes when you tap Alt
      Turn on "Stop a lone Alt tap from opening menu bars" in Settings, or
      switch the shortcut to Ctrl Ctrl.

  * It fills the wrong answer
      Raise "How sure it must be before filling on its own" in Settings, and
      it will ask more often instead of guessing.

  * It asks when it should just fill
      Lower that same setting.
"""


# ==========================================================================
#  THE WINDOWS
# ==========================================================================
# Four separate windows rather than one window with tabs: Answers, Settings,
# Help and About. Each opens on its own, and asking for one that is already
# open brings it forward instead of making a second copy.


class AppWindow:
    """A themed window that only ever exists once at a time."""

    TITLE = APP_NAME
    SIZE = "620x600"
    MIN = (460, 380)

    def __init__(self, root: tk.Tk, app):
        self.root = root
        self.app = app
        self.win = None

    @property
    def is_open(self) -> bool:
        return self.win is not None and self.win.winfo_exists()

    def open(self) -> None:
        """Show this window, closing whichever one was open before.

        Only ever one of these on screen: opening Settings puts Answers away
        rather than stacking a second window on top of it.
        """
        if self.is_open:
            self.win.deiconify()
            self.win.lift()
            self.win.focus_force()
            return
        for other in self.app.app_windows():
            if other is not self:
                other.close()
        win = tk.Toplevel(self.root)
        self.win = win
        win.title("%s %s \u2014 %s" % (APP_NAME, APP_VERSION, self.TITLE))
        win.geometry(self.SIZE)
        win.minsize(*self.MIN)
        win.configure(bg=BG)
        win.protocol("WM_DELETE_WINDOW", self.close)
        style_ttk(win)
        self.build(win)
        win.lift()
        win.focus_force()

    def close(self) -> None:
        if self.is_open:
            self.win.destroy()
        self.win = None

    def build(self, win) -> None:
        raise NotImplementedError

    # -- small shared pieces ---------------------------------------------
    def footer(self, parent, *buttons):
        """A row of buttons along the bottom. Rightmost is listed first."""
        bar = tk.Frame(parent, bg=BG)
        bar.pack(fill="x", side="bottom", padx=14, pady=12)
        self.status = tk.Label(bar, text="", bg=BG, fg=ACCENT, font=FONT_SMALL,
                               anchor="w")
        self.status.pack(side="left")
        for text, action, primary in buttons:
            button = tk.Button(bar, text=text, command=action, width=13,
                               relief="flat", borderwidth=0, font=FONT,
                               cursor="hand2", padx=10, pady=6,
                               bg=SELECT if primary else BG_ALT,
                               fg=SELECT_TEXT if primary else FG,
                               activebackground=SELECT if primary else CARD_BORDER,
                               activeforeground=SELECT_TEXT if primary else FG,
                               highlightthickness=0)
            button.pack(side="right", padx=(8, 0))
            base = SELECT if primary else BG_ALT
            hover = CARD_BORDER if not primary else SELECT
            button.bind("<Enter>", lambda e, h=hover: e.widget.config(bg=h))
            button.bind("<Leave>", lambda e, b=base: e.widget.config(bg=b))
        return bar

    def say(self, message: str, ms: int = 3000) -> None:
        if not self.is_open:
            return
        self.status.config(text=message)
        self.win.after(ms, lambda: self.status.config(text="")
                       if self.is_open else None)

    def scroller(self, parent):
        """A vertical scrolling area. Returns the frame to put content in."""
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        bar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=BG)
        inner.bind("<Configure>",
                   lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        window = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.bind("<Configure>",
                    lambda e: canvas.itemconfig(window, width=e.width))
        canvas.configure(yscrollcommand=bar.set)
        canvas.pack(side="left", fill="both", expand=True, padx=(4, 0))
        bar.pack(side="right", fill="y")

        def wheel(event):
            canvas.yview_scroll(int(-event.delta / 120), "units")
        canvas.bind("<MouseWheel>", wheel)
        inner.bind("<MouseWheel>", wheel)
        self._wheel = wheel
        return inner


def style_ttk(win) -> None:
    """clam draws light borders by default; paint every part of it dark."""
    style = ttk.Style(win)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass
    style.configure("TFrame", background=BG)
    style.configure("TScrollbar", background=BG_ALT, troughcolor=BG,
                    bordercolor=BG, arrowcolor=FG_DIM, lightcolor=BG_ALT,
                    darkcolor=BG_ALT)
    style.configure("TCombobox", fieldbackground=BG_ALT, background=BG_ALT,
                    foreground=FG, arrowcolor=FG_DIM, bordercolor=CARD_BORDER,
                    lightcolor=BG_ALT, darkcolor=BG_ALT, selectbackground=BG_ALT,
                    selectforeground=FG)
    win.option_add("*TCombobox*Listbox.background", BG_ALT)
    win.option_add("*TCombobox*Listbox.foreground", FG)
    win.option_add("*TCombobox*Listbox.selectBackground", SELECT)
    win.option_add("*TCombobox*Listbox.selectForeground", SELECT_TEXT)


# ==========================================================================
#  THE ANSWERS WINDOW
# ==========================================================================
# Search, edit, categorise and remove. Opens on its own, not as a
# tab, and asking for it twice brings the same window forward.

class AnswersWindow(AppWindow):
    """Search, edit, categorise and remove your answers.

    Rows are grouped by category. Only boxes you actually change are written
    back, so an import or a quick fm= add happening while this is open is
    never quietly undone.
    """

    TITLE = "Answers"
    SIZE = "760x680"
    MIN = (560, 420)

    def __init__(self, root, app):
        AppWindow.__init__(self, root, app)
        self._widgets = {}      # key -> getter
        self._loaded = {}       # what each box held when it was drawn
        self._query = ""

    def build(self, win) -> None:
        top = tk.Frame(win, bg=BG)
        top.pack(fill="x", padx=14, pady=(14, 8))

        tk.Label(top, text="\u2315", bg=BG, fg=FG_FAINT,
                 font=(UI, 14)).pack(side="left", padx=(0, 8))
        self.search = tk.StringVar()
        self.search.trace_add("write", lambda *_a: self._filter())
        entry = tk.Entry(top, textvariable=self.search, bg=BG_ALT, fg=FG,
                         insertbackground=FG, relief="flat", font=FONT)
        entry.pack(side="left", fill="x", expand=True, ipady=5)
        tk.Button(top, text="Clear", width=7, relief="flat", bg=BG_ALT, fg=FG,
                  font=FONT_SMALL, activebackground=CARD_BORDER,
                  command=lambda: self.search.set("")).pack(side="left",
                                                            padx=(6, 0))
        tk.Button(top, text="+ Add answer", relief="flat", bg=SELECT,
                  fg=SELECT_TEXT, activebackground=SELECT,
                  activeforeground=SELECT_TEXT, font=FONT_SMALL,
                  command=self._add).pack(side="left", padx=(10, 0))

        self.count = tk.Label(win, text="", bg=BG, fg=FG_DIM, font=FONT_SMALL,
                              anchor="w")
        self.count.pack(fill="x", padx=16, pady=(0, 6))

        self.footer(win,
                    ("Close", self.close, False),
                    ("Save", self.save, True),
                    ("Import\u2026", self.import_answers, False),
                    ("Export\u2026", self.export_answers, False))

        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(0, 4))
        self.rows_frame = self.scroller(body)
        self._render()

    # -- drawing -----------------------------------------------------------
    def _matches(self, field) -> bool:
        q = normalize(self._query)
        if not q:
            return True
        hay = " ".join([normalize(field.label), normalize(field.key),
                        normalize(field.category), normalize(field.value)]
                       + [normalize(a) for a in field.aliases])
        return q.replace(" ", "") in hay.replace(" ", "")

    def _render(self) -> None:
        for child in self.rows_frame.winfo_children():
            child.destroy()
        self._widgets.clear()
        self._loaded.clear()

        shown = 0
        for category in self.app.profile.categories():
            fields = [f for f in self.app.profile.in_category(category)
                      if self._matches(f)]
            if not fields:
                continue
            head = tk.Frame(self.rows_frame, bg=BG)
            head.pack(fill="x", pady=(12, 2), padx=2)
            tk.Label(head, text=category.upper(), bg=BG, fg=ACCENT,
                     font=(UI, 8, "bold"), anchor="w").pack(side="left")
            tk.Label(head, text="  %d" % len(fields), bg=BG, fg=FG_FAINT,
                     font=FONT_SMALL).pack(side="left")
            tk.Frame(self.rows_frame, bg=CARD_BORDER, height=1).pack(
                fill="x", padx=2, pady=(0, 4))
            for field in fields:
                self._row(field)
                shown += 1

        if not shown:
            tk.Label(self.rows_frame, bg=BG, fg=WARN, font=FONT,
                     text="Nothing matches \u201c%s\u201d" % self._query
                     ).pack(fill="x", padx=14, pady=20)

        filled = len(self.app.profile.filled())
        self.count.config(
            text="%d answers shown \u00b7 %d of %d have a value"
                 % (shown, filled, len(self.app.profile.fields)))

    def _row(self, field) -> None:
        row = tk.Frame(self.rows_frame, bg=BG)
        row.pack(fill="x", pady=2, padx=2)

        tk.Label(row, text=field.label, width=20, anchor="w", bg=BG, fg=FG,
                 font=FONT).pack(side="left")

        # remove and category sit on the right so the value box can stretch
        tk.Button(row, text="\u2715", width=2, relief="flat", bg=BG, fg=FG_FAINT,
                  activebackground=WARN, activeforeground=BG, font=FONT_SMALL,
                  command=lambda f=field: self._remove(f)).pack(side="right")

        picker = ttk.Combobox(row, width=13, state="readonly", font=FONT_SMALL,
                              values=self.app.profile.categories()
                              + ["\uff0b New category\u2026"])
        picker.set(field.category)
        picker.pack(side="right", padx=(6, 4))
        picker.bind("<<ComboboxSelected>>",
                    lambda _e, f=field, p=picker: self._recategorise(f, p))

        if field.multiline:
            box = tk.Text(row, height=3, bg=BG_ALT, fg=FG, insertbackground=FG,
                          relief="flat", font=FONT, wrap="word")
            box.insert("1.0", field.value)
            box.pack(side="left", fill="x", expand=True)
            self._widgets[field.key] = lambda b=box: b.get("1.0", "end-1c")
        else:
            var = tk.StringVar(value=field.value)
            tk.Entry(row, textvariable=var, bg=BG_ALT, fg=FG,
                     insertbackground=FG, relief="flat", font=FONT,
                     show="\u2022" if field.secret else "").pack(
                         side="left", fill="x", expand=True, ipady=4)
            self._widgets[field.key] = var.get
        self._loaded[field.key] = field.value

    def _filter(self) -> None:
        self.save(quiet=True)          # keep edits made before searching
        self._query = self.search.get().strip()
        self._render()

    # -- actions -----------------------------------------------------------
    def _recategorise(self, field, picker) -> None:
        """The combobox changed. Ask for a name if they picked New category."""
        chosen = picker.get()
        if chosen.endswith("New category…"):
            picker.set(field.category)
            name = simpledialog.askstring(
                "New category", "What should this group be called?",
                parent=self.win)
            if not name or not name.strip():
                return
            chosen = name.strip()[:30]
        self._recategorise_to(field, chosen)

    def _recategorise_to(self, field, category: str) -> None:
        """Move one answer into a category, creating it if it is new."""
        self.save(quiet=True)
        field.category = category
        self.app.profile.save()
        self.app.on_profile_changed(refresh_editor=False)
        self._render()
        self.say("Moved “%s” to %s" % (field.label, category))

    def _remove(self, field) -> None:
        """Ask first, unless there is nothing to lose."""
        shipped = field.key in DEFAULT_CATEGORY
        detail = ("\n\nIts value will be cleared. The answer itself stays, "
                  "ready for next time."
                  if shipped else "\n\nThis answer will be deleted.")
        if field.value.strip() and not messagebox.askyesno(
                "Form Buddy", "Remove “%s”?" % field.label + detail,
                parent=self.win):
            return
        self._remove_now(field)

    def _remove_now(self, field) -> None:
        """Shipped answers are emptied; ones you invented are deleted."""
        self.save(quiet=True)
        label = field.label
        if field.key in DEFAULT_CATEGORY:
            field.value = ""
        else:
            self.app.profile.fields.remove(field)
        self.app.profile.save()
        self.app.on_profile_changed(refresh_editor=False)
        self._render()
        self.say("Removed “%s”" % label)

    def _add(self) -> None:
        AddAnswer(self.win, self.app, on_done=self._after_add).run()

    def _after_add(self, field) -> None:
        self._render()
        self.say("Added \u201c%s\u201d" % field.label)

    # -- saving ------------------------------------------------------------
    def save(self, quiet: bool = False) -> None:
        """Write back only the boxes you actually changed."""
        if not self.is_open:
            return
        changed = 0
        for field in self.app.profile.fields:
            getter = self._widgets.get(field.key)
            if getter is None:
                continue
            try:
                typed = getter()
            except tk.TclError:
                continue               # the row was redrawn under us
            if typed != self._loaded.get(field.key, field.value):
                field.value = typed
                self._loaded[field.key] = typed
                changed += 1
        if changed:
            self.app.profile.save()
            self.app.on_profile_changed(refresh_editor=False)
        if not quiet:
            self.say("Saved \u2014 %d answer%s ready."
                     % (len(self.app.profile.filled()),
                        "" if len(self.app.profile.filled()) == 1 else "s"))

    def refresh(self) -> None:
        if self.is_open:
            self._render()

    def close(self) -> None:
        self.save(quiet=True)
        AppWindow.close(self)

    # -- files -------------------------------------------------------------
    def export_answers(self) -> None:
        self.save(quiet=True)
        message = export_profile(self.win, self.app.profile)
        if message:
            self.say(message, 4000)

    def import_answers(self) -> None:
        self.save(quiet=True)
        message = import_profile(self.win, self.app.profile)
        if message:
            self.app.on_profile_changed(refresh_editor=False)
            self._render()
            self.say(message, 5000)


class AddAnswer:
    """The little dialog behind + Add answer."""

    def __init__(self, parent, app, on_done=None):
        self.parent = parent
        self.app = app
        self.on_done = on_done

    def run(self) -> None:
        win = tk.Toplevel(self.parent)
        self.win = win
        win.title("Add an answer")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.parent)

        name, value = tk.StringVar(), tk.StringVar()
        cat = tk.StringVar(value=UNCATEGORISED)
        first = None
        for caption, var in (("What should this be called?", name),
                             ("The answer", value)):
            tk.Label(win, text=caption, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                     anchor="w").pack(fill="x", padx=16, pady=(12, 2))
            box = tk.Entry(win, textvariable=var, bg=BG_ALT, fg=FG,
                           insertbackground=FG, relief="flat", width=44,
                           font=FONT)
            box.pack(padx=16, ipady=5)
            first = first or box

        tk.Label(win, text="Category", bg=BG, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w").pack(fill="x", padx=16, pady=(12, 2))
        picker = ttk.Combobox(win, textvariable=cat, font=FONT, width=42,
                              values=self.app.profile.categories())
        picker.pack(padx=16)

        def finish(save):
            if save and name.get().strip() and value.get().strip():
                field = self.app.add_answer(name.get().strip(),
                                            value.get().strip(),
                                            category=cat.get().strip())
                win.destroy()
                if self.on_done:
                    self.on_done(field)
                return
            win.destroy()

        bar = tk.Frame(win, bg=BG)
        bar.pack(fill="x", padx=16, pady=14)
        tk.Button(bar, text="Add", width=10, relief="flat", bg=SELECT,
                  fg=SELECT_TEXT, command=lambda: finish(True)).pack(side="right")
        tk.Button(bar, text="Cancel", width=10, relief="flat", bg=BG_ALT, fg=FG,
                  command=lambda: finish(False)).pack(side="right", padx=(0, 8))
        win.bind("<Return>", lambda _e: finish(True))
        win.bind("<Escape>", lambda _e: finish(False))
        win.update_idletasks()
        win.lift()
        win.focus_force()
        if first:
            first.focus_set()


class SettingsWindow(AppWindow):
    """Theme, shortcut, and how eager the buddy is."""

    TITLE = "Settings"
    SIZE = "620x640"
    MIN = (480, 460)

    def build(self, win) -> None:
        self._vars = {}
        s = self.app.settings
        self.footer(win, ("Close", self.close, False), ("Save", self.save, True))
        wrap = tk.Frame(win, bg=BG)
        wrap.pack(fill="both", expand=True, padx=20, pady=(18, 4))

        tk.Label(wrap, text="Theme", bg=BG, fg=FG, font=FONT_BOLD,
                 anchor="w").pack(fill="x")
        tk.Label(wrap, text="Applies straight away.", bg=BG, fg=FG_DIM,
                 font=FONT_SMALL, anchor="w").pack(fill="x", pady=(0, 4))
        theme = tk.StringVar(value=s.get("theme", "dark"))
        row = tk.Frame(wrap, bg=BG)
        row.pack(fill="x", pady=(0, 14))
        for key, label in THEME_LABELS.items():
            tk.Radiobutton(row, text=label, variable=theme, value=key,
                           command=lambda v=theme: self._retheme(v.get()),
                           bg=BG, fg=FG, selectcolor=BG_ALT,
                           activebackground=BG, activeforeground=FG,
                           font=FONT).pack(side="left", padx=(0, 18))

        tk.Label(wrap, text="Summon the buddy with", bg=BG, fg=FG,
                 font=FONT_BOLD, anchor="w").pack(fill="x")
        tk.Label(wrap, text="Click into any box on any form, then tap this "
                           "twice.", bg=BG, fg=FG_DIM, font=FONT_SMALL,
                 anchor="w").pack(fill="x", pady=(0, 4))
        hotkey = tk.StringVar(value=s.get("hotkey", "double_alt"))
        self._vars["hotkey"] = hotkey
        for key, label in HOTKEY_LABELS.items():
            tk.Radiobutton(wrap, text=label, variable=hotkey, value=key,
                           bg=BG, fg=FG, selectcolor=BG_ALT,
                           activebackground=BG, activeforeground=FG,
                           font=FONT, anchor="w").pack(fill="x")

        self._checkbox(wrap, "suppress_solo_alt",
                       "Stop a lone Alt tap from opening menu bars",
                       "Recommended while using Alt Alt. Alt+Tab and every "
                       "other Alt shortcut keep working.")
        self._checkbox(wrap, "show_toasts",
                       "Show a little confirmation after filling", "")
        self._checkbox(wrap, "suggest_bar",
                       "Suggest answers above the taskbar as I type",
                       "A slim strip appears while you type a word that "
                       "matches one of your answers. Hold Alt and use the "
                       "arrow keys to take one.")

        tk.Label(wrap, text="Speed of the double tap", bg=BG, fg=FG,
                 font=FONT_BOLD, anchor="w").pack(fill="x", pady=(14, 0))
        gap = tk.IntVar(value=s.get("double_tap_ms", 450))
        self._vars["double_tap_ms"] = gap
        tk.Scale(wrap, from_=200, to=900, resolution=50, orient="horizontal",
                 variable=gap, bg=BG, fg=FG_DIM, troughcolor=BG_ALT,
                 highlightthickness=0, relief="flat", font=FONT_SMALL,
                 label="milliseconds between the two taps").pack(fill="x")

        tk.Label(wrap, text="How sure it must be before filling on its own",
                 bg=BG, fg=FG, font=FONT_BOLD, anchor="w").pack(fill="x",
                                                                pady=(12, 0))
        conf = tk.IntVar(value=s.get("auto_fill_threshold", 78))
        self._vars["auto_fill_threshold"] = conf
        tk.Scale(wrap, from_=50, to=100, resolution=1, orient="horizontal",
                 variable=conf, bg=BG, fg=FG_DIM, troughcolor=BG_ALT,
                 highlightthickness=0, relief="flat", font=FONT_SMALL,
                 label="lower = fills more often, higher = asks more often"
                 ).pack(fill="x")

    def _checkbox(self, parent, key, title, note) -> None:
        var = tk.BooleanVar(value=bool(self.app.settings.get(key, True)))
        self._vars[key] = var
        tk.Checkbutton(parent, text=title, variable=var, bg=BG, fg=FG,
                       selectcolor=BG_ALT, activebackground=BG,
                       activeforeground=FG, font=FONT,
                       anchor="w").pack(fill="x", pady=(12, 0))
        if note:
            tk.Label(parent, text=note, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                     anchor="w", justify="left", wraplength=520).pack(
                         fill="x", padx=(24, 0))

    def _retheme(self, name) -> None:
        self.app.set_theme(name)
        self.close()
        self.open()               # redraw this window in the new colours

    def save(self) -> None:
        for key, var in self._vars.items():
            self.app.settings[key] = var.get()
        self.app.save_settings()
        self.app.tray.refresh()
        self.say("Saved.")


class HelpWindow(AppWindow):
    """The manual, with worked examples."""

    TITLE = "Help"
    SIZE = "700x720"
    MIN = (520, 420)

    def build(self, win) -> None:
        self.footer(win, ("Close", self.close, True))
        body = tk.Frame(win, bg=BG)
        body.pack(fill="both", expand=True, padx=10, pady=(10, 4))
        inner = self.scroller(body)
        for block in HELP_TEXT.strip().split("\n\n"):
            lines = block.split("\n")
            heading = lines[0].isupper() and len(lines[0]) < 60
            indented = block.startswith("   ")
            if not indented:
                block = " ".join(line.strip() for line in lines)
            tk.Label(inner, text=block, bg=BG,
                     fg=FG_DIM if indented else FG,
                     font=FONT_BOLD if heading else
                     (FONT_MONO if indented else FONT),
                     justify="left", anchor="w", wraplength=590).pack(
                         fill="x", padx=14,
                         pady=(14, 2) if heading else (0, 7))


class AboutWindow(AppWindow):
    """Version, who made it, and where your files are."""

    TITLE = "About"
    SIZE = "560x480"
    MIN = (460, 380)

    def build(self, win) -> None:
        self.footer(win, ("Close", self.close, True))
        wrap = tk.Frame(win, bg=BG)
        wrap.pack(fill="both", expand=True, padx=24, pady=22)

        tk.Label(wrap, text=APP_NAME, bg=BG, fg=FG,
                 font=(UI, 20, "bold"), anchor="w").pack(fill="x")
        tk.Label(wrap, text="Version %s" % APP_VERSION, bg=BG, fg=ACCENT,
                 font=FONT_BOLD, anchor="w").pack(fill="x", pady=(2, 16))

        for label, value in (("Developed by", APP_AUTHOR),
                             ("Website", APP_WEBSITE),
                             ("Released", APP_RELEASED),
                             ("Signed in as", SESSION.username or "nobody"),
                             ("Your answers", str(USERS_DIR)),
                             ("Settings", str(SETTINGS_PATH))):
            row = tk.Frame(wrap, bg=BG)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=label, bg=BG, fg=FG_DIM, font=FONT_SMALL,
                     width=13, anchor="w").pack(side="left")
            cell = tk.Label(row, text=value, bg=BG, fg=FG, font=FONT,
                            anchor="w", justify="left", wraplength=360)
            cell.pack(side="left", fill="x", expand=True)
            if value == APP_WEBSITE:
                cell.config(fg=SELECT, cursor="hand2")
                cell.bind("<Button-1>",
                          lambda _e: webbrowser.open("https://" + APP_WEBSITE))

        tk.Frame(wrap, bg=CARD_BORDER, height=1).pack(fill="x", pady=16)
        tk.Label(wrap, bg=BG, fg=FG_DIM, font=FONT_SMALL, justify="left",
                 anchor="w", wraplength=470,
                 text="Your answers are encrypted with your password using "
                      "AES-GCM, and the key is derived with scrypt. The "
                      "password itself is never stored anywhere, in any form, "
                      "so it cannot be recovered if you forget it.\n\n"
                      "Nothing is ever sent anywhere. There is no network "
                      "code in this program at all.").pack(fill="x")


# ==========================================================================
#  TRAY ICON
# ==========================================================================
# System-tray presence: the only chrome Form Buddy needs while it works.

def _icon_image(on: bool):
    """Green while listening, red while switched off."""
    return make_icon(ICON_ON if on else ICON_OFF, 64)


class Tray:
    def __init__(self, app):
        self.app = app
        self.icon = pystray.Icon(
            "formbuddy", _icon_image(app.enabled), self._title(), self._menu())

    def _title(self) -> str:
        state = "on" if self.app.enabled else "off"
        who = SESSION.username or "locked"
        return "%s — %s — %s  (%s in any box)" % (
            APP_NAME, who, state, self.app.hotkey_label)

    def _menu(self) -> pystray.Menu:
        return pystray.Menu(
            pystray.MenuItem(
                lambda _: "Enabled  (%s)" % self.app.hotkey_label,
                lambda: self.app.post("toggle"),
                checked=lambda _: self.app.enabled, default=True),
            pystray.MenuItem(
                "Side panel",
                lambda: self.app.post("panel"),
                checked=lambda _: self.app.panel.visible),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Edit answers…", lambda: self.app.post("editor")),
            pystray.MenuItem("Reload answers", lambda: self.app.post("reload")),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Lock / switch person",
                             lambda: self.app.post("lock")),
            pystray.MenuItem("Quit", lambda: self.app.post("quit")),
        )

    def start(self) -> None:
        threading.Thread(target=self.icon.run, name="formbuddy-tray",
                         daemon=True).start()

    def refresh(self) -> None:
        try:
            self.icon.icon = _icon_image(self.app.enabled)
            self.icon.title = self._title()
            self.icon.update_menu()
        except Exception:
            pass

    def stop(self) -> None:
        try:
            self.icon.stop()
        except Exception:
            pass


# ==========================================================================
#  PUTTING IT ALL TOGETHER
# ==========================================================================
# Form Buddy — click a box, tap Alt twice, get your answer typed in.

# A second double-tap on the same box within this window means "not that one,
# show me the next best guess".
CYCLE_SECONDS = 6.0

# Two shorthands you can type straight into any box. Both accept fm= or fb=,
# and they are told apart by the second "=":
#
#   fm=last name=Perera   two parts -> save that answer
#   fb=last name           one part  -> a placeholder, to be filled in
#
QUICK_ADD = re.compile(r"^\s*f[mb]\s*=\s*([^=]{1,60}?)\s*=\s*(.+?)\s*$",
                       re.IGNORECASE | re.DOTALL)
# The words after fb= are grabbed generously; how many of them are actually
# the answer's name is decided in code, because in a sentence like
# "email me at fb=email and I will reply" only the first word is the name.
PLACEHOLDER = re.compile(
    r"f[mb]\s*=\s*(?=[A-Za-z])((?:(?!f[mb]\s*=)[A-Za-z0-9 _/-]){1,48})",
    re.IGNORECASE)
MAX_NAME_WORDS = 4

# Never walk a runaway document forever.
MAX_PLACEHOLDERS = 60


class FormBuddy:
    def __init__(self):
        self.settings = load_settings()
        self.profile = Profile()          # nothing until someone signs in
        self.enabled = bool(self.settings.get("start_enabled", True))

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_NAME)

        self.toast = Toast(self.root)
        self.palette = Palette(self.root, self)
        self.panel = Panel(self.root, self)
        self.suggest = SuggestionBar(self.root, self)
        self.answers = AnswersWindow(self.root, self)
        self.settings_window = SettingsWindow(self.root, self)
        self.help_window = HelpWindow(self.root, self)
        self.about_window = AboutWindow(self.root, self)
        self._pid = os.getpid()
        self._last_target = None      # last box outside our own windows

        self.events: "queue.Queue" = queue.Queue()
        self.hook = HotkeyHook(self.settings, self._on_trigger,
                               self._on_suggest_key)
        self.hook.enabled = self.enabled
        self.tray = Tray(self)

        # When a double-tap turned a typed word into a search, this is what
        # has to be rubbed out before the answer is typed in its place.
        self._plan = None              # how the palette's choice gets applied
        self._template = None          # the fb=name run currently in progress
        self._last_key = None         # identity of the last box we filled
        self._last_ranked = []
        self._last_index = 0
        self._last_time = 0.0

    # -- plumbing ---------------------------------------------------------
    @property
    def hotkey_label(self) -> str:
        return HOTKEY_LABELS.get(self.settings.get("hotkey", "double_alt"),
                                 "Alt Alt")

    def run(self) -> None:
        apply_theme(self.settings.get("theme", "dark"))
        if not self.sign_in():
            return                        # they closed the lock screen
        self.hook.start()
        self.tray.start()
        self.root.after(20, self._pump)
        self.root.after(150, self.panel.start)
        self.root.after(900, self._watch_typing)
        if self.settings.get("panel_visible"):
            self.root.after(300, self.panel.show)
        if not self.profile.filled():
            self.root.after(400, self._first_run)
        else:
            self.root.after(600, self._greet)
        self.root.mainloop()

    def sign_in(self) -> bool:
        """Ask who this is and unlock their vault. False means they gave up."""
        login = Login(self.root)
        answer = login.run()
        self._login_moved = login.moved
        if answer is None:
            self.root.quit()
            return False
        username, key, payload = answer
        SESSION.start(username, key)
        self.profile = Profile.from_payload(payload)
        if getattr(self, "_login_moved", 0):
            self.root.after(900, lambda n=self._login_moved: self.toast.show(
                "%d answers moved into your encrypted vault" % n, "ok", 4000))
        self.settings["last_user"] = username     # a name, never a password
        self.save_settings()
        return True

    def lock(self) -> None:
        """Forget the key and everything it opened, then ask again."""
        self.palette.close()
        self.panel.hide()
        for window in (self.answers, self.settings_window,
                       self.help_window, self.about_window):
            window.close()
        self.profile = Profile()
        SESSION.end()
        self.tray.refresh()
        if self.sign_in():
            self.on_profile_changed()
            self.tray.refresh()
            self._greet()

    def _first_run(self) -> None:
        self.answers.open()
        self.toast.show("Add a few answers, then click any form box and "
                        "tap %s" % self.hotkey_label, "info", 4000)

    def _greet(self) -> None:
        """Say hello somewhere visible, so a silent start is never mistaken
        for a failed one."""
        self.toast.show(
            "Form Buddy is on — %d answers ready. Tap %s in any box."
            % (len(self.profile.filled()), self.hotkey_label), "ok", 4000)

    def post(self, kind, payload=None) -> None:
        """Hand work to the Tk thread from the hook or tray thread."""
        self.events.put((kind, payload))

    def _pump(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                try:
                    self._dispatch(kind, payload)
                except Exception as exc:      # never let one bad box kill the app
                    self.toast.show("Something went wrong: %s" % exc, "warn")
        except queue.Empty:
            pass
        self.root.after(20, self._pump)

    def _dispatch(self, kind, payload) -> None:
        if kind == "trigger":
            self._handle_trigger()
        elif kind == "panel":
            self.panel.toggle()
        elif kind == "search":
            self._plan = {"ctx": self._last_target, "consume": "",
                          "selected": False}
            self.palette.open(self._last_target)
        elif kind == "template":
            self._template_advance(payload)
        elif kind == "toast":
            message, level, rect = payload
            if self.settings.get("show_toasts", True) or level == "warn":
                self.toast.show(message, level, rect=rect)
        elif kind == "editor":
            self.answers.open()
        elif kind == "reload":
            self.profile = Profile.load()
            self.panel.refresh()
            self.toast.show("Answers reloaded (%d ready)"
                            % len(self.profile.filled()), "info")
        elif kind == "toggle":
            self.set_enabled(not self.enabled)
        elif kind == "suggest":
            self.on_suggest_key(payload)
        elif kind == "settings":
            self.settings_window.open()
        elif kind == "help":
            self.help_window.open()
        elif kind == "about":
            self.about_window.open()
        elif kind == "lock":
            self.lock()
        elif kind == "quit":
            self.shutdown()

    # -- hook callbacks (these run on the hook thread) ---------------------
    def _on_trigger(self) -> None:
        self.post("trigger")

    def _on_suggest_key(self, action) -> None:
        self.post("suggest", action)

    # -- knowing which box to fill -----------------------------------------
    def inspect_target(self, deep: bool = True, strict: bool = False):
        """The box the user is working in — never one of our own windows.

        Our overlays are all no-activate, so focus normally stays put; the
        remembered fallback only matters while one of the real windows is up.

        `strict` refuses that fallback. Use it when deciding whether to type
        into something: a box you clicked ten minutes ago is not where you
        want an answer to land now, and copying to the clipboard instead is
        always the safer miss.
        """
        ctx = inspect_focused(deep=deep)
        if ctx is None or window_pid(ctx.hwnd) == self._pid:
            return None if strict else self._last_target
        self._last_target = ctx
        return ctx

    # -- fb=name placeholders, filled one at a time -------------------------
    def _all_text(self, ctx) -> str:
        """Everything in the box, not just the word under the caret."""
        try:
            pattern = ctx.control.GetPattern(auto.PatternId.TextPattern)
            return pattern.DocumentRange.GetText(200000) or ""
        except Exception:
            return ctx.current_value or ""

    def _swap_marker(self, ctx, marker: str, value: str) -> bool:
        """Select the literal marker wherever it sits, and type over it.

        Going through the text pattern rather than the caret is what lets a
        placeholder halfway down a paragraph be replaced without disturbing
        anything around it.
        """
        try:
            pattern = ctx.control.GetPattern(auto.PatternId.TextPattern)
            found = pattern.DocumentRange.FindText(marker, False, True)
            if found is None:
                return False
            found.Select()
        except Exception:
            return self._swap_by_value(ctx, marker, value)
        time.sleep(0.06)
        try:
            type_text(value, int(self.settings.get("type_delay_ms", 1)))
        except Exception:
            return False
        return True

    def _swap_by_value(self, ctx, marker: str, value: str) -> bool:
        """Fallback for boxes with no text pattern: rewrite the whole value."""
        current = ctx.current_value or ""
        if marker not in current:
            return False
        return set_value_directly(ctx, current.replace(marker, value, 1))

    def _next_placeholder(self, text: str):
        """The first fb=name still in the text: (literal, name, answer or None).

        The name is the longest run of words after fb= that actually names one
        of your answers, so "fb=last name and thanks" reads as "last name".
        """
        answers = self.profile.filled()
        for match in PLACEHOLDER.finditer(text):
            raw = match.group(1)
            words = raw.split()
            # "fb=email and thanks" names the answer "email": stop at the
            # first word that means nothing on its own.
            for stop, word in enumerate(words):
                if is_filler(word):
                    words = words[:stop]
                    break
            if not words:
                continue
            # An "=" right after a short name makes this fm=name=value, the
            # add shorthand rather than a placeholder. A long run of words
            # ending in "=" is just this match colliding with the next fb=.
            if (len(words) <= MAX_NAME_WORDS
                    and text[match.end(1):match.end(1) + 1] == "="):
                continue

            def literal_for(count):
                pos = 0
                for word in words[:count]:
                    pos = raw.index(word, pos) + len(word)
                return text[match.start():match.start(1) + pos]

            limit = min(MAX_NAME_WORDS, len(words))
            for count in range(limit, 0, -1):
                name = " ".join(words[:count])
                field = sole_match(answers, name)
                if field is not None:
                    return literal_for(count), name, field
            # Nothing resolves outright; ask about the longest name that at
            # least turns something up, and failing that the first word alone.
            for count in range(limit, 0, -1):
                name = " ".join(words[:count])
                if search(answers, name):
                    return literal_for(count), name, None
            return literal_for(1), words[0], None
        return None

    def _start_template(self, ctx) -> bool:
        """Kick off a run if there are any fb=name placeholders in the box."""
        if self._next_placeholder(self._all_text(ctx)) is None:
            return False
        self._template = {"ctx": ctx, "done": 0, "asked": 0, "last": None}
        self._template_step()
        return True

    def _template_step(self) -> None:
        """Handle the first placeholder still standing, then come back."""
        run = self._template
        if run is None:
            return
        ctx = run["ctx"]
        if run["done"] + run["asked"] >= MAX_PLACEHOLDERS:
            return self._finish_template("stopped after %d" % MAX_PLACEHOLDERS)

        resolved = self._next_placeholder(self._all_text(ctx))
        if resolved is None:
            return self._finish_template()

        marker, name, field = resolved
        if marker == run["last"]:
            # The previous pass could not replace this one; do not loop on it.
            return self._finish_template("could not fill %s" % name, warn=True)

        if field is not None:
            run["last"] = marker

            def swap():
                ok = self._swap_marker(ctx, marker, field.value)
                self.post("template", ok)

            threading.Thread(target=swap, daemon=True).start()
            return

        # Ambiguous or unknown: ask, and pick the run up again after the click.
        run["asked"] += 1
        self._plan = {"ctx": ctx, "marker": marker}
        self.palette.open(ctx, name, note="placeholder: %s" % name)

    def _template_advance(self, ok: bool) -> None:
        run = self._template
        if run is None:
            return
        if not ok:
            return self._finish_template("could not fill that placeholder",
                                         warn=True)
        run["done"] += 1
        self.root.after(260, self._template_step)

    def _finish_template(self, note: str = "", warn: bool = False) -> None:
        run, self._template = self._template, None
        if run is None:
            return
        filled = run["done"]
        if note:
            self.toast.show("Filled %d, then %s" % (filled, note),
                            "warn" if warn else "info")
        elif filled:
            self.toast.show("Filled %d placeholder%s"
                            % (filled, "" if filled == 1 else "s"), "ok")

    # -- fm=label=value, typed straight into any box -----------------------
    def _field_for_label(self, label: str):
        """The one existing answer that goes by this name, if there is one."""
        wanted = normalize(label)
        hits = []
        for f in self.profile.fields:
            names = [normalize(f.label), normalize(f.key)] +                 [normalize(a) for a in f.aliases]
            if wanted in names:
                hits.append(f)
        return hits[0] if len(hits) == 1 else None

    def _try_quick_add(self, ctx) -> bool:
        """Type `fm=last name=Perera` anywhere, tap twice, and it is saved.

        Faster than opening the answers window when you just thought of one.
        """
        source = (ctx.selection or ctx.current_value or "")
        match = QUICK_ADD.match(source)
        if not match:
            return False
        label, value = match.group(1).strip(), match.group(2).strip()
        if not label or not value:
            return False

        field = self._field_for_label(label)
        if field is None:
            key = "custom_" + re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            if self.profile.get(key) is not None:
                key += "_2"
            field = Field(key=key, label=label.strip().capitalize(),
                          aliases=[label.lower()])
            self.profile.fields.append(field)
            verb = "Added"
        else:
            verb = "Updated"
            if category:
                field.category = category
        field.value = value
        self.profile.save()
        self.panel.refresh()

        had_selection = bool(ctx.selection.strip())
        length = len(source)

        def tidy():
            # Take the instruction back out of the form; it was never meant
            # to be part of what you are filling in.
            time.sleep(0.03)
            try:
                if had_selection:
                    tap(VK_DELETE, extended=True)
                else:
                    tap(VK_END, extended=True)
                    backspace(length)
            except Exception:
                pass
            self.post("toast", ("%s “%s” = %s" % (verb, field.label,
                                                  field.preview(24)),
                                "ok", ctx.rect))

        threading.Thread(target=tidy, daemon=True).start()
        return True

    # -- the main act ------------------------------------------------------
    def _handle_trigger(self) -> None:
        """Everything a double-tap can mean, in the order it is tried."""
        if self.palette.is_open:             # tap again to dismiss
            self.palette.close()
            self.palette_cancelled()
            return

        # Strict: only a box that has the caret right now counts. Without
        # this an answer could land in something focused minutes ago.
        ctx = self.inspect_target(strict=True)

        if ctx is not None and ctx.editable:
            # 1. fm=name=value -> save that answer and tidy the line away
            if self._try_quick_add(ctx):
                return
            # 2. fb=name placeholders -> fill every one of them
            if self._start_template(ctx):
                return

        answers = self.profile.filled()
        if not answers:
            self.toast.show("No answers saved yet — opening your answer list",
                            "warn")
            self.answers.open()
            return

        # 3. something typed or highlighted -> use it as the search
        query = ""
        if ctx is not None and ctx.editable:
            query = (ctx.selection or ctx.caret_word).strip()

        if query and len(query) <= 40:
            selected = bool(ctx.selection.strip())
            only = sole_match(answers, query)
            if only is not None:
                # One clear answer: straight in, no window.
                self._plan = None
                self._fill(only, ctx, consume=query, selected=selected)
                return
            self._plan = {"ctx": ctx, "consume": query, "selected": selected}
            self.palette.open(ctx, query)
            return

        # 4. nothing typed -> open the search window on the best guess order
        self._plan = {"ctx": ctx, "consume": "", "selected": False}
        self.palette.open(ctx)

    def _identity(self, ctx) -> tuple:
        return (ctx.hwnd, ctx.rect, tuple(ctx.texts))

    def _reset_cycle(self) -> None:
        self._last_key, self._last_ranked = None, []
        self._last_index, self._last_time = 0, 0.0

    def ordered_answers(self, ctx):
        """Every answer, best guess for this box first."""
        answers = self.profile.filled()
        if ctx is None or not ctx.texts:
            return answers
        best = [f for f, _s, _t in rank(answers, ctx.texts)]
        return best + [f for f in answers if f not in best]

    def palette_chose(self, field) -> None:
        """Enter in the search window: put the answer where it belongs."""
        plan, self._plan = self._plan, None
        if plan is None:
            return self.copy_to_clipboard(field)

        if plan.get("marker"):
            ctx = plan["ctx"]

            def swap():
                set_foreground(ctx.hwnd)
                time.sleep(0.08)
                focus_control(ctx)
                ok = self._swap_marker(ctx, plan["marker"], field.value)
                self.post("template", ok)

            threading.Thread(target=swap, daemon=True).start()
            return

        ctx = plan.get("ctx")
        if ctx is None or not ctx.editable:
            return self.copy_to_clipboard(field)

        self._reset_cycle()
        self._fill(field, ctx, consume=plan.get("consume", ""),
                   selected=plan.get("selected", False), refocus=True)

    def palette_cancelled(self) -> None:
        plan, self._plan = self._plan, None
        if plan and plan.get("marker"):
            self._finish_template("you closed the search", warn=False)

    # -- side panel --------------------------------------------------------
    def fill_from_panel(self, field) -> None:
        """A click in the sidebar copies. Only the search window writes."""
        self.copy_to_clipboard(field)

    def copy_to_clipboard(self, field) -> None:
        self.root.clipboard_clear()
        self.root.clipboard_append(field.value)
        self.root.update_idletasks()
        self.toast.show("%s copied — paste it wherever you like" % field.label,
                        "ok")

    def add_answer(self, label: str, value: str, category: str = ""):
        """Create the answer, or update it if one already goes by that name."""
        field = self._field_for_label(label)
        if field is None:
            key = "custom_" + re.sub(r"[^a-z0-9]+", "_", label.lower()).strip("_")
            if self.profile.get(key) is not None:
                key += "_2"
            field = Field(key=key, label=label.capitalize(),
                          aliases=[label.lower()],
                          category=category or UNCATEGORISED)
            self.profile.fields.append(field)
            verb = "Added"
        else:
            verb = "Updated"
            if category:
                field.category = category
        field.value = value
        self.profile.save()
        self.on_profile_changed()
        self.toast.show("%s “%s”" % (verb, field.label), "ok")
        return field

    def fill_from_suggestion(self, field, word: str) -> None:
        """Alt+arrow picked a chip: swap the half-typed word for the answer."""
        ctx = self.inspect_target(strict=True)
        if ctx is None or not ctx.editable:
            return self.copy_to_clipboard(field)
        self._reset_cycle()
        self._fill(field, ctx, consume=word, selected=False)

    def _watch_typing(self) -> None:
        """Look at the word being typed and offer anything that matches."""
        try:
            self._suggest_tick()
        except Exception:
            pass
        self.root.after(SUGGEST_POLL_MS, self._watch_typing)

    def _suggest_tick(self) -> None:
        if not (self.enabled and self.settings.get("suggest_bar", True)):
            return self.suggest.hide()
        if self.palette.is_open or self._template is not None:
            return self.suggest.hide()
        if any(w.is_open for w in self.app_windows()):
            return self.suggest.hide()

        ctx = self.inspect_target(deep=False, strict=True)
        if ctx is None or not ctx.editable:
            return self.suggest.hide()

        word = (ctx.selection or ctx.caret_word).strip()
        if len(word) < SUGGEST_MIN_CHARS or len(word) > 30:
            return self.suggest.hide()
        if word.lower().startswith(("fb=", "fm=")):
            return self.suggest.hide()      # that is the placeholder syntax

        hits = search(self.profile.filled(), word)[:SUGGEST_MAX]
        if not hits:
            return self.suggest.hide()
        self.suggest.show(hits, word)

    def on_suggest_key(self, action: str) -> None:
        """Alt plus an arrow, forwarded from the keyboard hook."""
        if action == "left":
            self.suggest.move(-1)
        elif action == "right":
            self.suggest.move(1)
        elif action == "use":
            self.suggest.choose()

    def app_windows(self):
        """The four full windows. Only one of them is ever open."""
        return (self.answers, self.settings_window, self.help_window,
                self.about_window)

    def set_theme(self, name: str) -> None:
        """Swap the palette and rebuild anything already drawn in the old one."""
        self.settings["theme"] = name
        self.save_settings()
        apply_theme(name)

        was_visible = self.panel.visible
        for widget in (self.panel, self.palette, self.toast):
            win = getattr(widget, "win", None)
            if win is not None:
                try:
                    win.destroy()
                except tk.TclError:
                    pass
                widget.win = None
        self.panel.visible = False
        self.panel._rows = []
        self.palette._rows = []
        if was_visible:
            self.panel.show()
        self.toast.show("Theme: %s" % THEME_LABELS.get(name, name), "ok")

    def on_profile_changed(self, refresh_editor: bool = True) -> None:
        """Something changed the answers. Show it everywhere at once."""
        if refresh_editor:
            self.answers.refresh()
        self.panel.refresh()

    # -- filling -----------------------------------------------------------
    def _fill(self, field, ctx, note: str = "", consume: str = "",
              selected: bool = False, refocus: bool = False) -> None:
        """Type the answer in. Never clears the box.

        Three shapes, all of them additive rather than destructive:
          * something highlighted  — typing replaces just the highlight
          * a typed search word    — rub out exactly that word, type the answer
          * neither                — insert at the caret, leaving the rest alone
        """
        delay = int(self.settings.get("type_delay_ms", 1))
        text = field.value
        to_delete = 0 if selected else len(consume)

        def worker():
            if refocus:
                # We took the keyboard for the search window; hand it back.
                set_foreground(ctx.hwnd)
                time.sleep(0.09)
                focus_control(ctx)
            time.sleep(0.03)                 # let the caret settle
            ok = True
            try:
                if to_delete:
                    backspace(to_delete)
                    time.sleep(0.02)
                type_text(text, delay)
            except Exception:
                ok = set_value_directly(ctx, text)
            message = "%s → %s" % (field.label, field.preview(28))
            if note:
                message += "   (%s)" % note
            self.post("toast", (message if ok else
                                "Could not type into that box",
                                "ok" if ok else "warn", ctx.rect))

        threading.Thread(target=worker, daemon=True).start()

    # -- state -------------------------------------------------------------
    def set_enabled(self, on: bool) -> None:
        self.enabled = on
        self.hook.enabled = on
        if not on:
            if self.palette.is_open:
                self.palette.close()
            self._panel_was_visible = self.panel.visible
            self.panel.hide()
        elif getattr(self, "_panel_was_visible", False):
            self.panel.show()
        self.tray.refresh()
        self.toast.show("Form Buddy is %s" % ("on" if on else "off"),
                        "ok" if on else "info")

    def save_settings(self) -> None:
        save_settings(self.settings)

    def shutdown(self) -> None:
        try:
            self.profile.save()
            self.settings["start_enabled"] = self.enabled
            self.save_settings()
        finally:
            self.tray.stop()
            self.hook.stop()
            self.root.quit()
            self.root.destroy()


def already_running() -> bool:
    """Two copies would install two keyboard hooks and type everything twice."""
    import ctypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # CreateMutexW does not clear the last error when it succeeds, so an
    # unrelated ERROR_ALREADY_EXISTS left behind by something earlier (the
    # mkdir in data_dir(), for one) would read as a second instance.
    kernel32.SetLastError(0)
    handle = kernel32.CreateMutexW(None, False, "Global\\FormBuddySingleInstance")
    error = ctypes.get_last_error()
    # The handle is deliberately leaked: Windows releases it when we exit,
    # which is exactly the lifetime we want the lock to have.
    return bool(handle) and error == 183           # ERROR_ALREADY_EXISTS


def main() -> None:
    if already_running():
        print("Form Buddy is already running — look for its tray icon "
              "under the ^ arrow next to the clock.")
        return
    FormBuddy().run()

if __name__ == "__main__":
    main()
