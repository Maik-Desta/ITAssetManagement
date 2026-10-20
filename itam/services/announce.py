"""Spoken branch-offline announcements for the NOC voice alerts, in English and French.

The browser reads the text aloud with its own speech engine (Web Speech API), so nothing leaves the bank's network.
Codes are spelled digit by digit so both voices read them the same way ("0 0 0 9", not "nine").
"""

from __future__ import annotations

from collections import Counter

# Region code → (English, French with article).
REGIONS = {
    "ADA": ("the Adamawa region", "la région de l'Adamaoua"),
    "CEN": ("the Centre region", "la région du Centre"),
    "EST": ("the East region", "la région de l'Est"),
    "EXN": ("the Far North region", "la région de l'Extrême-Nord"),
    "LIT": ("the Littoral region", "la région du Littoral"),
    "NOR": ("the North region", "la région du Nord"),
    "NOW": ("the North-West region", "la région du Nord-Ouest"),
    "OUE": ("the West region", "la région de l'Ouest"),
    "SOW": ("the South-West region", "la région du Sud-Ouest"),
    "SUD": ("the South region", "la région du Sud"),
}
# Asset type → ((English singular, plural), (French singular, plural)).
DEVICES = {
    "RTR": (("router", "routers"), ("routeur", "routeurs")),
    "SWT": (("switch", "switches"), ("commutateur", "commutateurs")),
    "SRV": (("server", "servers"), ("serveur", "serveurs")),
    "FWL": (("firewall", "firewalls"), ("pare-feu", "pare-feu")),
    "UPS": (("UPS power unit", "UPS power units"), ("onduleur", "onduleurs")),
    "ATM": (("ATM", "ATMs"), ("guichet automatique", "guichets automatiques")),
    "STO": (("storage array", "storage arrays"), ("baie de stockage", "baies de stockage")),
    "WAP": (("wireless access point", "wireless access points"), ("point d'accès Wi-Fi", "points d'accès Wi-Fi")),
    "EUD": (("workstation", "workstations"), ("poste de travail", "postes de travail")),
    "ENV": (("environment sensor", "environment sensors"), ("capteur d'environnement", "capteurs d'environnement")),
}
STATES = {"down": ("down", "hors service"), "unreachable": ("not responding", "sans réponse"),
          "degraded": ("degraded", "en mode dégradé")}
LEVELS = [("Level 1: NOC and regional engineer", "niveau 1 : NOC et ingénieur régional"),
          ("Level 2: regional IT lead", "niveau 2 : responsable informatique régional"),
          ("Level 3: Head of Infrastructure and CIO", "niveau 3 : responsable de l'infrastructure et DSI"),
          ("CEO level: the Chief Executive", "niveau Direction générale : le Directeur général")]
TOP = [("Level 1", "niveau 1"), ("Level 2", "niveau 2"), ("Level 3", "niveau 3"), ("the CEO level", "la Direction générale")]
CHANNELS = {"VOICE": ("phone call", "appel téléphonique"), "SMS": ("SMS", "SMS"), "EMAIL": ("email", "e-mail"),
            "SYSTEM": ("in-app message", "notification dans l'application"), "CHAT": ("Teams", "Teams")}


def _join(items: list[str], word: str) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + f" {word} " + items[-1]


def _spell(code: str) -> str:
    return " ".join(code)


def _duration(minutes: float | None) -> tuple[str, str]:
    m = int(minutes or 0)
    if m < 60:
        return f"{m} minute{'s' if m != 1 else ''}", f"{m} minute{'s' if m != 1 else ''}"
    h = round(m / 60)
    if h < 72:
        return f"{h} hour{'s' if h != 1 else ''}", f"{h} heure{'s' if h != 1 else ''}"
    d = h // 24
    return f"{d} days", f"{d} jours"


def _devices(assets: list[dict]) -> tuple[str, str]:
    """'2 routers and 1 switch not responding' / '2 routeurs et 1 commutateur sans réponse'."""
    en, fr = [], []
    for state, (st_en, st_fr) in STATES.items():
        counts = Counter(x["asset"].asset_type for x in assets if x["state"] == state)
        if not counts:
            continue
        words_en = [f"{n} {DEVICES.get(t, ((t, t), (t, t)))[0][n != 1]}" for t, n in counts.most_common()]
        words_fr = [f"{n} {DEVICES.get(t, ((t, t), (t, t)))[1][n != 1]}" for t, n in counts.most_common()]
        en.append(f"{_join(words_en, 'and')} {st_en}")
        fr.append(f"{_join(words_fr, 'et')} {st_fr}")
    return "; ".join(en), " ; ".join(fr)


def branch_offline(g: dict, assets: list[dict]) -> dict:
    """English and French text for one offline-branch incident from the NOC overview."""
    b, lead = g["branch"], g["lead"]
    a = lead["alert"]
    region_en, region_fr = REGIONS.get(b.region.code, (f"the {b.region.name} region", f"la région {b.region.name}"))
    name = b.name.replace("&", "and")
    name_fr = b.name.replace("&", "et").removesuffix(" Branch")
    for_en, for_fr = _duration(g["age_min"])

    en = [f"Attention. Critical alert: branch offline. Branch number {_spell(b.code)}, {name}, in {region_en}, "
          f"has lost all network connection and has been offline for {for_en}."]
    fr = [f"Attention. Alerte critique : agence hors ligne. L'agence numéro {_spell(b.code)}, {name_fr}, dans {region_fr}, "
          f"a perdu toute connexion réseau et est hors ligne depuis {for_fr}."]

    dev_en, dev_fr = _devices(assets)
    if dev_en:
        en.append(f"Affected equipment: {dev_en}.")
        fr.append(f"Équipements touchés : {dev_fr}.")

    done = [s["level"] for s in lead["path"] if s["state"] == "done"]
    overdue = [s["level"] for s in lead["path"] if s["state"] == "overdue"]
    pending = [s["level"] for s in lead["path"] if s["state"] == "due"]
    if done:
        top_en, top_fr = TOP[max(done)]
        en.append(f"Escalation status: the incident has reached {top_en}. "
                  f"Notified so far: {'; '.join(LEVELS[i][0] for i in done)}.")
        fr.append(f"État de l'escalade : l'incident a atteint {'le ' if max(done) < 3 else ''}{top_fr}. "
                  f"Déjà notifiés : {' ; '.join(LEVELS[i][1] for i in done)}.")
    if overdue:
        en.append(f"Overdue: {'; '.join(LEVELS[i][0] for i in overdue)}.")
        fr.append(f"En retard : {' ; '.join(LEVELS[i][1] for i in overdue)}.")
    if pending:
        en.append(f"Next escalation: {LEVELS[pending[0]][0]}.")
        fr.append(f"Prochaine escalade : {LEVELS[pending[0]][1]}.")
    if a.acknowledged_at:
        who = a.acknowledged_by.full_name if a.acknowledged_by else "the NOC"
        en.append(f"The alert has been acknowledged by {who}.")
        fr.append(f"L'alerte a été prise en charge par {who}.")
    else:
        en.append("The alert has not yet been acknowledged.")
        fr.append("L'alerte n'a pas encore été prise en charge.")

    people, channels = [], []
    for e in a.escalations:
        people += [p for p in e.recipients or [] if p not in people]
        channels += [c for c in e.channels or [] if c not in channels and c in CHANNELS]
    if people:
        how_en = f" by {_join([CHANNELS[c][0] for c in channels], 'and')}" if channels else ""
        how_fr = f" par {_join([CHANNELS[c][1] for c in channels], 'et')}" if channels else ""
        en.append(f"Notified: {_join(people, 'and')}{how_en}.")
        fr.append(f"Personnes notifiées : {_join(people, 'et')}{how_fr}.")
    ticket = (a.ticket_ref or "").split("-")[-1].lstrip("0")
    if ticket.isdigit():
        en.append(f"Incident ticket {ticket}.")
        fr.append(f"Ticket d'incident {ticket}.")
    return {"key": a.ticket_ref or f"A{a.id}", "en": " ".join(en), "fr": " ".join(fr)}
