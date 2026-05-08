"""
InsightGuard — Nexon Technologies OCEAN Psychometric Profiles
=============================================================
Provides Big Five (OCEAN) personality profiles for all 55 Nexon employees.
These are loaded at app startup via psychometric_scorer.load_from_list()
and feed into the PERS scoring pipeline.

Profiles are assigned based on role characteristics and seeded randomness
(deterministic — same profile every run). A few employees have high-risk
personality profiles (low C, low A, high N) to make PERS detection
meaningful during demos.

Risk formula (from psychometric_scorer.py):
    psych_risk = (100-C)*0.35 + (100-A)*0.35 + N*0.30

Profiles:
  - Normal staff:  C≈65-80, A≈60-80, N≈20-40  → psych_risk ≈ 20-35
  - Medium risk:   C≈45-60, A≈45-60, N≈45-60  → psych_risk ≈ 45-55
  - High risk:     C≈20-40, A≈20-40, N≈65-80  → psych_risk ≈ 70-85
"""

from __future__ import annotations


# ---------------------------------------------------------------------------
# Nexon employee OCEAN profiles
# Format: user_id, name, O, C, E, A, N
# ---------------------------------------------------------------------------

NEXON_OCEAN_PROFILES = [
    # ── Engineering ──────────────────────────────────────────────────────
    # Normal profiles
    {"user_id": "alex.morgan",       "name": "Alex Morgan",        "O": 72, "C": 78, "E": 62, "A": 74, "N": 22},
    {"user_id": "sam.patel",         "name": "Sam Patel",           "O": 68, "C": 82, "E": 55, "A": 71, "N": 25},
    {"user_id": "jordan.lee",        "name": "Jordan Lee",          "O": 65, "C": 74, "E": 68, "A": 76, "N": 30},
    {"user_id": "casey.kim",         "name": "Casey Kim",           "O": 70, "C": 76, "E": 58, "A": 69, "N": 28},
    # Medium risk — slightly higher neuroticism / lower agreeableness
    {"user_id": "riley.chen",        "name": "Riley Chen",          "O": 75, "C": 55, "E": 60, "A": 52, "N": 48},
    {"user_id": "drew.johnson",      "name": "Drew Johnson",        "O": 60, "C": 71, "E": 64, "A": 66, "N": 35},
    {"user_id": "taylor.wong",       "name": "Taylor Wong",         "O": 66, "C": 73, "E": 57, "A": 70, "N": 29},
    {"user_id": "morgan.davis",      "name": "Morgan Davis",        "O": 69, "C": 80, "E": 61, "A": 75, "N": 20},
    {"user_id": "quinn.harris",      "name": "Quinn Harris",        "O": 71, "C": 67, "E": 53, "A": 63, "N": 38},
    # High psychometric risk — disgruntled developer (low C, low A, high N)
    {"user_id": "avery.martin",      "name": "Avery Martin",        "O": 80, "C": 28, "E": 45, "A": 25, "N": 75},

    # ── Finance ──────────────────────────────────────────────────────────
    # Normal
    {"user_id": "james.carter",      "name": "James Carter",        "O": 55, "C": 82, "E": 65, "A": 78, "N": 20},
    {"user_id": "sarah.chen",        "name": "Sarah Chen",          "O": 60, "C": 85, "E": 70, "A": 80, "N": 18},
    {"user_id": "michael.torres",    "name": "Michael Torres",      "O": 52, "C": 79, "E": 60, "A": 74, "N": 25},
    {"user_id": "lisa.nguyen",       "name": "Lisa Nguyen",         "O": 58, "C": 84, "E": 68, "A": 79, "N": 22},
    {"user_id": "david.kim",         "name": "David Kim",           "O": 54, "C": 77, "E": 62, "A": 72, "N": 28},
    {"user_id": "emma.wilson",       "name": "Emma Wilson",         "O": 56, "C": 81, "E": 66, "A": 77, "N": 21},
    {"user_id": "ryan.patel",        "name": "Ryan Patel",          "O": 62, "C": 76, "E": 72, "A": 70, "N": 30},
    # High risk — financial insider (low C, hostile, stressed)
    {"user_id": "olivia.brown",      "name": "Olivia Brown",        "O": 65, "C": 32, "E": 50, "A": 30, "N": 72},

    # ── HR ───────────────────────────────────────────────────────────────
    {"user_id": "jessica.moore",     "name": "Jessica Moore",       "O": 70, "C": 80, "E": 82, "A": 85, "N": 18},
    {"user_id": "daniel.taylor",     "name": "Daniel Taylor",       "O": 65, "C": 74, "E": 78, "A": 80, "N": 22},
    {"user_id": "sophia.jackson",    "name": "Sophia Jackson",      "O": 68, "C": 78, "E": 80, "A": 82, "N": 20},
    {"user_id": "ethan.white",       "name": "Ethan White",         "O": 62, "C": 72, "E": 74, "A": 76, "N": 25},
    {"user_id": "ava.martinez",      "name": "Ava Martinez",        "O": 66, "C": 76, "E": 76, "A": 78, "N": 23},
    # Medium risk HR — may leak employee data
    {"user_id": "noah.thompson",     "name": "Noah Thompson",       "O": 72, "C": 50, "E": 70, "A": 48, "N": 52},

    # ── IT / Security ────────────────────────────────────────────────────
    # Normal IT staff
    {"user_id": "mia.thomas",        "name": "Mia Thomas",          "O": 68, "C": 80, "E": 58, "A": 72, "N": 24},
    {"user_id": "jacob.garcia",      "name": "Jacob Garcia",        "O": 70, "C": 82, "E": 60, "A": 74, "N": 22},
    {"user_id": "isabella.robinson", "name": "Isabella Robinson",   "O": 64, "C": 76, "E": 62, "A": 70, "N": 28},
    {"user_id": "mason.clark",       "name": "Mason Clark",         "O": 66, "C": 78, "E": 56, "A": 68, "N": 26},
    {"user_id": "charlotte.lewis",   "name": "Charlotte Lewis",     "O": 72, "C": 84, "E": 62, "A": 76, "N": 20},
    # High risk IT — privileged access + high psychometric risk (rogue sysadmin)
    {"user_id": "liam.anderson",     "name": "Liam Anderson",       "O": 78, "C": 25, "E": 42, "A": 22, "N": 80},

    # ── Sales ────────────────────────────────────────────────────────────
    # Normal
    {"user_id": "emily.walker",      "name": "Emily Walker",        "O": 72, "C": 76, "E": 88, "A": 80, "N": 22},
    {"user_id": "lucas.hall",        "name": "Lucas Hall",          "O": 68, "C": 72, "E": 85, "A": 76, "N": 25},
    {"user_id": "amelia.allen",      "name": "Amelia Allen",        "O": 66, "C": 74, "E": 82, "A": 78, "N": 24},
    {"user_id": "oliver.young",      "name": "Oliver Young",        "O": 70, "C": 70, "E": 84, "A": 74, "N": 28},
    {"user_id": "harper.hernandez",  "name": "Harper Hernandez",    "O": 74, "C": 78, "E": 90, "A": 82, "N": 20},
    {"user_id": "elijah.king",       "name": "Elijah King",         "O": 65, "C": 68, "E": 80, "A": 72, "N": 30},
    {"user_id": "abigail.wright",    "name": "Abigail Wright",      "O": 67, "C": 71, "E": 83, "A": 75, "N": 26},
    {"user_id": "james.lopez",       "name": "James Lopez",         "O": 69, "C": 73, "E": 86, "A": 77, "N": 23},
    # Medium risk — sales rep looking to leave, may take client data
    {"user_id": "aiden.lee",         "name": "Aiden Lee",           "O": 75, "C": 48, "E": 88, "A": 46, "N": 55},

    # ── Marketing ────────────────────────────────────────────────────────
    {"user_id": "sophia.hill",       "name": "Sophia Hill",         "O": 80, "C": 76, "E": 84, "A": 80, "N": 22},
    {"user_id": "william.scott",     "name": "William Scott",       "O": 78, "C": 72, "E": 80, "A": 76, "N": 26},
    {"user_id": "mia.green",         "name": "Mia Green",           "O": 76, "C": 74, "E": 78, "A": 74, "N": 24},
    {"user_id": "jackson.adams",     "name": "Jackson Adams",       "O": 74, "C": 70, "E": 82, "A": 72, "N": 28},
    {"user_id": "scarlett.baker",    "name": "Scarlett Baker",      "O": 82, "C": 75, "E": 86, "A": 78, "N": 20},
    {"user_id": "henry.nelson",      "name": "Henry Nelson",        "O": 70, "C": 68, "E": 76, "A": 70, "N": 32},

    # ── Legal ────────────────────────────────────────────────────────────
    {"user_id": "victoria.carter",   "name": "Victoria Carter",     "O": 65, "C": 86, "E": 60, "A": 82, "N": 18},
    {"user_id": "sebastian.mitchell","name": "Sebastian Mitchell",  "O": 62, "C": 83, "E": 56, "A": 79, "N": 21},
    # Medium risk — compliance officer under pressure
    {"user_id": "grace.perez",       "name": "Grace Perez",         "O": 68, "C": 52, "E": 58, "A": 50, "N": 50},
    {"user_id": "joseph.roberts",    "name": "Joseph Roberts",      "O": 60, "C": 80, "E": 55, "A": 76, "N": 22},

    # ── Executive ────────────────────────────────────────────────────────
    {"user_id": "robert.anderson",   "name": "Robert Anderson",     "O": 75, "C": 88, "E": 82, "A": 80, "N": 15},
    {"user_id": "jennifer.williams", "name": "Jennifer Williams",   "O": 70, "C": 90, "E": 78, "A": 84, "N": 12},
    {"user_id": "michael.johnson",   "name": "Michael Johnson",     "O": 78, "C": 86, "E": 80, "A": 78, "N": 18},

    # ── Operations ───────────────────────────────────────────────────────
    {"user_id": "luna.turner",       "name": "Luna Turner",         "O": 66, "C": 78, "E": 68, "A": 74, "N": 26},
    {"user_id": "eli.phillips",      "name": "Eli Phillips",        "O": 64, "C": 76, "E": 66, "A": 72, "N": 28},
    {"user_id": "nora.campbell",     "name": "Nora Campbell",       "O": 62, "C": 74, "E": 64, "A": 70, "N": 30},
]


def load_nexon_profiles() -> int:
    """
    Load all Nexon employee OCEAN profiles into the global psychometric store.
    Call once at app startup (after init_psychometrics).
    Returns number of profiles loaded.
    """
    from psychometric_scorer import get_store
    store = get_store()
    count = store.load_from_list(NEXON_OCEAN_PROFILES)
    print(f"[Nexon PERS] Loaded {count} OCEAN profiles for Nexon employees.")
    return count


def get_high_risk_employees() -> list[str]:
    """Returns user IDs of Nexon employees with psychometric_risk >= 60."""
    from psychometric_scorer import get_store
    store = get_store()
    high = []
    for p in NEXON_OCEAN_PROFILES:
        uid = p["user_id"]
        risk = store.get_risk(uid)
        if risk >= 60:
            high.append(uid)
    return high


if __name__ == "__main__":
    # Self-test: print all profiles with computed risk
    load_nexon_profiles()
    from psychometric_scorer import get_store
    store = get_store()
    print(f"\nNexon Employee Psychometric Profiles ({len(NEXON_OCEAN_PROFILES)} total)")
    print("=" * 70)
    for p in sorted(NEXON_OCEAN_PROFILES, key=lambda x: -(
        (100 - x["C"]) * 0.35 + (100 - x["A"]) * 0.35 + x["N"] * 0.30
    )):
        risk = store.get_risk(p["user_id"])
        label = "HIGH RISK" if risk >= 65 else "MEDIUM" if risk >= 45 else "normal"
        print(f"  {p['user_id']:<28} O={p['O']:3d} C={p['C']:3d} E={p['E']:3d} "
              f"A={p['A']:3d} N={p['N']:3d}  risk={risk:5.1f}  {label}")
