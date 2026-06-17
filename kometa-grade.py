#!/usr/bin/env python3
# kometa-grade.py
# Cover quality assessment for kometa steganography.
# Analyzes carrier density, capacity, distribution, and spellcheck risk.
#
# Usage:
#   python3 kometa-grade.py <file>
#   cat file.txt | python3 kometa-grade.py
#   python3 kometa-grade.py <file> --verbose
#   python3 kometa-grade.py <file> --message-len 48

import sys, os, re
sys.path.insert(0, os.path.dirname(__file__))
from kometa import DICT, DEAD_ZONE_START, DEAD_ZONE_END, DENSITY_BUCKETS

# ── FREQUENCY WORDLIST ────────────────────────
# Top 2000 English words by Google Trillion Word Corpus frequency
# Tier 1 (1-500): high-frequency function words — breaking these is very glaring
# Tier 2 (501-2000): common words — still noticeable if altered
# Tier 3 (2001-10000): valid but less frequent — lowest spellcheck risk

FREQ_TIER1 = set("""
the of and to a in for is on that by this with i you it not or be are from at as 
your all have new more an was we will home can us about if page my has search free 
but our one other do no information time they site he up may what which their news 
out use any there see only so his when contact here business who web also now help 
get pm view online c e first am been would how were me s services some these click 
its like service x than find price date back top people had list name just over state 
year day into email two health n world re next used go b work last most products 
music buy data make them should product system post her city t add policy number such 
please available copyright support message after best software then jan good video well 
d where info rights public books high school through m each links she review years 
order very privacy book items company r read group sex need many user said de does 
set under general research university january mail full map reviews program life know 
games way days management p part could great united hotel real f item international 
center ebay must store travel comments made development report off member details line 
terms before hotels did send right type because local those using results office 
education national car design take posted internet address community within states area 
want phone dvd shipping reserved subject between forum family l long based w code show 
o even black check special prices website index being women much sign file link open 
today technology south case project same pages uk version section own found sports house 
related security both g county american photo game members power while care network down 
computer systems three total place end following download h him without per access think 
north resources current posts big media law control water history pictures size art 
personal since including guide shop directory board location change white text small rating 
rate government children during usa return students v shopping account times sites level 
digital profile previous form events love old john main call hours image department title 
description non k y insurance another why shall property class cd still money quality every 
listing content country private little visit save tools low reply customer december compare 
movies include college value article york man card jobs provide j food source author 
different press u learn sale around print course job canada process teen room stock training 
too credit point join science men categories advanced west sales look english left team 
estate box conditions select windows photos gay thread week category note live large gallery 
table register however june october november market library really action start series model 
features air industry plan human provided tv yes required second hot accessories cost movie 
forums march la september better say questions july yahoo going medical test friend come dec 
server pc study application cart staff articles san feedback again play looking issues april 
never users complete street topic comment financial things working against standard tax person 
below mobile less got blog party payment equipment login student let programs offers legal 
above recent park stores side act problem red give memory performance social q august quote 
language story sell options experience rates create key body young america important field few 
east paper single ii age activities club example girls additional password z latest something 
road gift question changes night ca hard texas oct pay four poker status browse issue range 
building seller court february always result audio light write war nov offer blue groups al 
easy given files event release analysis request fax china making picture needs possible might 
professional yet month major star areas future space committee hand sun cards problems london 
washington meeting rss become interest id child keep enter california porn share similar garden 
schools million added reference companies listed baby learning energy run delivery net popular 
term film stories put computers journal reports co try welcome central images president notice 
god original head radio until cell color self council away includes track australia discussion 
archive once others entertainment agreement format least society months log safety friends sure 
faq trade edition cars messages marketing tell further updated association able having provides 
david fun already green studies close common drive specific several gold feb living sep 
collection called short arts lot ask display limited powered solutions means director daily beach 
past natural whether due et electronics five upon period planning database says official weather 
mar land average done technical window france pro region island record direct microsoft conference 
environment records st district calendar costs style url front statement update parts aug ever 
downloads early miles sound resource present applications either ago document word works material 
bill apr written talk federal hosting rules final adult tickets thing centre requirements via 
cheap nude kids finance true minutes else mark third rock gifts europe reading topics bad 
individual tips plus auto cover usually edit together videos percent fast function fact unit 
getting global tech meet far economic en player projects lyrics often subscribe submit germany 
amount watch included feel though bank risk thanks everything deals various words linux jul 
production commercial james weight town heart advertising received choose treatment newsletter 
archives points knowledge magazine error camera jun girl currently construction toys registered 
clear golf receive domain methods chapter makes protection policies loan wide beauty manager india 
position taken sort listings models michael known half cases step engineering florida simple quick 
none wireless license paul friday lake whole annual published later basic sony shows corporate 
google church method purchase customers active response practice hardware figure materials fire 
holiday chat enough designed along among death writing speed html countries loss face brand 
discount higher effects created remember standards oil bit yellow political increase advertise 
kingdom base near environmental thought stuff french storage oh japan doing loans shoes entry
""".split())

FREQ_TIER2 = set("""
magazine rock wall street king dark deep blue light line point read dance move green 
white black red brown yellow orange purple pink grey gold silver bronze house door window 
room kitchen living bedroom bathroom office classroom church hospital school library museum 
gallery restaurant cafe shop store market bank post office police fire hospital doctor nurse 
teacher student professor scientist engineer lawyer judge politician president king queen 
prince princess duke duchess earl count baron nobleman lady gentleman master servant slave 
worker farmer rancher miner fisherman hunter trader merchant banker priest monk nun 
brother sister father mother son daughter husband wife boyfriend girlfriend friend 
companion neighbor citizen resident immigrant refugee exile criminal prisoner patient 
victim witness judge jury lawyer court trial verdict sentence crime punishment law rule 
regulation statute law code constitution bill act decree mandate order command instruction 
direction guidance advice recommendation suggestion proposal petition motion amendment 
resolution declaration statement proclamation announcement advertisement notice warning alarm 
signal message memo letter email document file folder archive library database table record 
entry item list catalog inventory collection exhibit display show performance play movie 
film television radio podcast audiobook ebook book magazine newspaper journal magazine 
publication edition version revision update upgrade patch fix modification alteration change 
transformation translation adaptation adaptation adoption adaptation customization configuration 
installation activation deactivation deployment implementation execution evaluation assessment 
analysis analysis analysis examination investigation inspection observation monitoring 
surveillance recording documentation notation annotation commentary explanation description 
narration story tale legend myth fable allegory parable anecdote account history background 
timeline calendar schedule calendar timetable itinerary agenda program plan project task 
job position occupation profession career vocation calling purpose goal objective aim target 
intention motivation intention rationale reasoning logic argument debate discussion 
conversation dialogue monologue speech address sermon lecture talk presentation briefing 
report summary abstract summary outline structure framework model diagram chart graph map 
route path trail track trail trajectory course direction orientation location position 
placement arrangement organization hierarchy system structure classification category type 
kind sort variety assortment selection collection assembly group team squad battalion 
regiment company corporation organization institution establishment society community club 
association league union federation confederation alliance partnership coalition network 
chain link connection relationship correlation comparison contrast similarity difference 
distinction differentiation separation separation isolation separation isolation isolation 
connection connection connection link link link bond bond bond tie tie tie attachment 
attachment attachment connection connection connection relationship relationship relationship
""".split())

# ── CARRIER LOOKUP ────────────────────────────

_LOOKUP = {}
for _i, (_l, _c) in enumerate(zip(DICT["lat"], DICT["cyr"])):
    _LOOKUP[_l] = ("lat", _i)
    _LOOKUP[_c] = ("cyr", _i)

# ── ANALYSIS FUNCTIONS ────────────────────────

def _extract_carriers(text: str) -> tuple[list[int], dict]:
    """
    Return (positions, observed) where:
      positions = list of character indices that are carriers
      observed  = dict mapping position → 0 (cyr) or 1 (ell) if pre-existing
    """
    positions, observed = [], {}
    for i, ch in enumerate(text):
        if ch not in _LOOKUP: continue
        script, _ = _LOOKUP[ch]
        positions.append(i)
        if script != "lat": observed[i] = 0 if script == "cyr" else 1
    return positions, observed

def _carrier_count(positions: list[int]) -> int:
    return len(positions)

def _eligible_carriers(positions: list[int]) -> int:
    """Carriers after dead-zone trim."""
    n = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    return hi - lo

def _pre_existing_carriers(observed: dict) -> tuple[int, int]:
    """Return (cyr_count, ell_count) of pre-existing non-Latin carriers."""
    cyr = sum(1 for v in observed.values() if v == 0)
    ell = sum(1 for v in observed.values() if v == 1)
    return cyr, ell

def _bucket_distribution(positions: list[int], n_buckets: int = DENSITY_BUCKETS) -> list[int]:
    """
    Divide eligible carriers into n_buckets, return carrier count per bucket.
    """
    n = len(positions)
    lo = int(n * DEAD_ZONE_START)
    hi = n - int(n * DEAD_ZONE_END)
    eligible = positions[lo:hi]
    
    if not eligible:
        return []
    
    bucket_size = len(eligible) / n_buckets
    buckets = [
        eligible[int(i * bucket_size) : int((i + 1) * bucket_size)]
        for i in range(n_buckets)
    ]
    return [len(b) for b in buckets]

def _bucket_balance(bucket_counts: list[int]) -> tuple[str, float]:
    """
    Return (verdict, max_min_ratio) describing bucket balance.
    Even = ratio < 2.0, Uneven = 2.0-3.0, Very uneven = > 3.0
    """
    if not bucket_counts or all(c == 0 for c in bucket_counts):
        return "empty", 0.0
    
    non_zero = [c for c in bucket_counts if c > 0]
    if not non_zero:
        return "empty", 0.0
    
    max_c = max(non_zero)
    min_c = min(non_zero)
    ratio = max_c / min_c if min_c > 0 else float('inf')
    
    if ratio < 2.0:
        return "even", ratio
    elif ratio < 3.0:
        return "uneven", ratio
    else:
        return "very uneven", ratio

def _capacity_bytes(eligible: int) -> int:
    """
    Capacity in bytes: (eligible - 16) / 8, capped to 0.
    The 16 comes from the header being reserved.
    """
    body_bits = max(0, eligible - 16)
    return body_bits // 8

def _bits_per_1000_chars(text_len: int, eligible: int) -> float:
    """Return bits per 1000 characters for easy comparison."""
    if text_len == 0:
        return 0.0
    return (eligible / text_len) * 1000

def _find_word_boundaries(text: str) -> list[tuple[int, int, str]]:
    """
    Find word boundaries in text. Return list of (start, end, word).
    Words are contiguous sequences of letters/numbers.
    """
    words = []
    i = 0
    while i < len(text):
        if text[i].isalpha() or text[i].isdigit():
            start = i
            while i < len(text) and (text[i].isalpha() or text[i].isdigit()):
                i += 1
            word = text[start:i].lower()
            words.append((start, i, word))
        else:
            i += 1
    return words

def _word_boundary_risk(text: str, positions: list[int]) -> tuple[dict, list]:
    """
    Check carriers that fall inside words against frequency tiers.
    Return (tier_counts, risk_items) where:
      tier_counts = {1: N, 2: M, 3: K, ...}
      risk_items = [(tier, word, position, carrier_char), ...]
    """
    words = _find_word_boundaries(text)
    word_map = {}
    for start, end, word in words:
        for pos in range(start, end):
            word_map[pos] = (word, start, end)
    
    pos_set = set(positions)
    tier_counts = {1: 0, 2: 0, 3: 0}
    risk_items = []
    
    for pos in positions:
        if pos not in word_map:
            continue
        
        word, word_start, word_end = word_map[pos]
        
        # Determine tier
        if word in FREQ_TIER1:
            tier = 1
        elif word in FREQ_TIER2:
            tier = 2
        else:
            tier = 3
        
        tier_counts[tier] += 1
        carrier_ch = text[pos]
        risk_items.append((tier, word, pos, carrier_ch))
    
    # Sort by tier (descending risk) then by position
    risk_items.sort(key=lambda x: (-x[0], x[2]))
    
    return tier_counts, risk_items

def _verdict(capacity: int, tier1_count: int, balance: str, eligible: int, positions: int) -> tuple[str, str]:
    """
    Determine verdict (USABLE, MARGINAL, UNUSABLE) and reason.
    
    USABLE:
      - eligible >= 16 (header fits)
      - capacity > 0
      - balance != "very uneven"
      - tier1_count <= 1 (0-1 high-risk carriers)
    
    MARGINAL:
      - eligible >= 16
      - capacity > 0 but < 5 bytes (tight)
      - OR tier1_count 2-3 (some high-risk)
      - OR balance == "uneven"
    
    UNUSABLE:
      - eligible < 16 (header doesn't fit)
      - OR capacity == 0
      - OR balance == "very uneven" + tier1_count > 2
    """
    
    if eligible < 16:
        return "UNUSABLE", "insufficient carriers for header (need 16, have %d)" % eligible
    
    if capacity == 0:
        return "UNUSABLE", "no body capacity after header and dead zones"
    
    if balance == "very uneven" and tier1_count > 2:
        return "UNUSABLE", "very uneven distribution + high spellcheck risk"
    
    if balance == "very uneven":
        return "MARGINAL", "very uneven bucket distribution (carrier density is biased)"
    
    if tier1_count >= 4:
        return "MARGINAL", "%d carriers in high-frequency words (spellcheck risk)" % tier1_count
    
    if tier1_count >= 2:
        return "MARGINAL", "%d carriers in high-frequency words" % tier1_count
    
    if balance == "uneven":
        return "MARGINAL", "somewhat uneven distribution"
    
    if capacity < 5:
        return "MARGINAL", "tight capacity (%d bytes)" % capacity
    
    return "USABLE", "good capacity and distribution"

# ── OUTPUT FORMATTING ────────────────────────

def _format_default(
    text: str,
    positions: list[int],
    observed: dict,
    eligible: int,
    capacity: int,
    buckets: list[int],
    balance: str,
    tier_counts: dict,
    verdict: str,
    reason: str,
    message_len: int = None
) -> str:
    
    total_chars = len(text)
    carrier_count = len(positions)
    cyr, ell = _pre_existing_carriers(observed)
    bpp = _bits_per_1000_chars(total_chars, eligible)
    
    lines = [
        "",
        f"kometa-grade: {carrier_count} carriers found",
        "",
        f"  document length:     {total_chars:,} chars",
        f"  carriers found:       {carrier_count:>3}   (1 per {total_chars//max(1,carrier_count)} chars)",
        f"  dead zones (10/10%):  -{int(carrier_count * (DEAD_ZONE_START + DEAD_ZONE_END)):>2}    →  {eligible:>3} eligible",
        f"  header reserved:       -16   →  {max(0, eligible-16):>3} body bits available",
        f"  capacity:              {capacity:>2} bytes  ({max(0, eligible-16)} bits ÷ 8, floor)",
        "",
    ]
    
    if message_len is not None:
        bits_needed = message_len * 8
        bits_available = max(0, eligible - 16)
        if bits_needed <= bits_available:
            lines.append(f"  message-len check ({message_len} bytes):")
            lines.append(f"    bits needed:         {bits_needed}")
            lines.append(f"    bits available:      {bits_available}")
            lines.append(f"    ✓ FIT")
            lines.append("")
        else:
            shortage = bits_needed - bits_available
            lines.append(f"  message-len check ({message_len} bytes):")
            lines.append(f"    bits needed:         {bits_needed}")
            lines.append(f"    bits available:      {bits_available}")
            lines.append(f"    ✗ INSUFFICIENT — need {shortage} more bits ({(shortage+7)//8} more bytes)")
            lines.append("")
    
    lines.append(f"  bucket balance:       {balance:15} (ratio {buckets[buckets.index(max(buckets))]/max(min(buckets), 1):.1f}:1)")
    lines.append(f"  pre-existing cyr/ell: {cyr} / {ell}       (clean baseline)")
    
    risk_level = "high" if tier_counts[1] > 1 else "medium" if tier_counts[1] + tier_counts[2] > 2 else "low"
    lines.append(f"  spellcheck risk:      {risk_level:12} ({tier_counts[1]} tier-1, {tier_counts[2]} tier-2, {tier_counts[3]} tier-3)")
    
    lines.append("")
    lines.append(f"  bits per 1000 chars:  {bpp:.1f}")
    lines.append("")
    lines.append(f"  verdict: {verdict} — {reason}")
    lines.append("")
    
    return "\n".join(lines)

def _format_verbose(
    text: str,
    positions: list[int],
    observed: dict,
    eligible: int,
    capacity: int,
    buckets: list[int],
    balance: str,
    tier_counts: dict,
    verdict: str,
    reason: str,
    risk_items: list,
    message_len: int = None
) -> str:
    
    out = _format_default(text, positions, observed, eligible, capacity, buckets, balance, tier_counts, verdict, reason, message_len)
    
    # Add verbose sections
    lines = out.split("\n")
    
    # Insert before verdict
    insert_idx = len(lines) - 3
    
    # Bucket distribution
    bucket_str = "  bucket distribution: " + "[" + ",".join(f"{c:>2}" for c in buckets) + "]"
    lines.insert(insert_idx, bucket_str)
    insert_idx += 1
    
    # Pre-existing script breakdown
    cyr, ell = _pre_existing_carriers(observed)
    lat = len(positions) - cyr - ell
    lines.insert(insert_idx, "")
    lines.insert(insert_idx, "  per-script carrier counts (in cover):")
    insert_idx += 2
    lines.insert(insert_idx, f"    lat (inactive pool):  {lat}")
    insert_idx += 1
    lines.insert(insert_idx, f"    cyr (pre-existing):   {cyr}")
    insert_idx += 1
    lines.insert(insert_idx, f"    ell (pre-existing):   {ell}")
    insert_idx += 1
    
    # Word boundary risk detail
    if risk_items:
        lines.insert(insert_idx, "")
        lines.insert(insert_idx, "  word-boundary risk (carriers in common words):")
        insert_idx += 2
        
        for tier, word, pos, ch in risk_items[:10]:  # Show top 10
            tier_label = ["???", "HIGH", "MEDIUM", "LOW"][min(3, tier)]
            lines.insert(insert_idx, f"    tier {tier} ({tier_label:6}): '{word}' @ pos {pos}")
            insert_idx += 1
        
        if len(risk_items) > 10:
            lines.insert(insert_idx, f"    ... and {len(risk_items) - 10} more")
            insert_idx += 1
    
    lines.insert(insert_idx, "")
    
    return "\n".join(lines)

# ── CLI ───────────────────────────────────────

def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Analyze cover text quality for kometa steganography",
        add_help=False
    )
    parser.add_argument("file", nargs="?", default=None, help="File to analyze (or stdin)")
    parser.add_argument("--verbose", action="store_true", help="Show detailed analysis")
    parser.add_argument("--message-len", type=int, default=None, help="Check if specific message size fits")
    
    args = parser.parse_args()
    
    # Read input
    if args.file:
        try:
            text = open(args.file, encoding="utf-8").read()
        except FileNotFoundError:
            sys.stderr.write(f"Error: file not found: {args.file}\n")
            sys.exit(1)
    else:
        text = sys.stdin.read()
    
    text = text.rstrip()
    
    # Analysis
    positions, observed = _extract_carriers(text)
    carrier_count = _carrier_count(positions)
    eligible = _eligible_carriers(positions)
    capacity = _capacity_bytes(eligible)
    buckets = _bucket_distribution(positions)
    balance, ratio = _bucket_balance(buckets)
    tier_counts, risk_items = _word_boundary_risk(text, positions)
    verdict, reason = _verdict(capacity, tier_counts[1], balance, eligible, len(positions))
    
    # Output
    if args.verbose:
        output = _format_verbose(text, positions, observed, eligible, capacity, buckets, balance, tier_counts, verdict, reason, risk_items, args.message_len)
    else:
        output = _format_default(text, positions, observed, eligible, capacity, buckets, balance, tier_counts, verdict, reason, args.message_len)
    
    sys.stdout.write(output)
    sys.stderr.write(f"{verdict}\n")
    
    # Exit code: 0 if USABLE, 1 otherwise
    sys.exit(0 if verdict == "USABLE" else 1)

if __name__ == "__main__":
    main()
