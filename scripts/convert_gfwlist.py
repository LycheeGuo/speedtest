#!/usr/bin/env python3
import base64
import re
import sys
from pathlib import Path
from urllib.parse import urlparse


def decode_gfwlist(input_path: Path) -> str:
    raw = input_path.read_text(encoding="utf-8", errors="ignore")
    raw = raw.strip()

    # GFWList normally is base64 encoded.
    # Add padding if needed.
    padding = "=" * ((4 - len(raw) % 4) % 4)

    try:
        decoded = base64.b64decode(raw + padding).decode("utf-8", errors="ignore")
        return decoded
    except Exception:
        # Fallback: treat as plain text.
        return raw


def normalize_domain(domain: str) -> str:
    domain = domain.strip().lower()

    domain = domain.lstrip(".")
    domain = domain.rstrip(".")
    domain = domain.replace("\\", "")

    # Remove leading wildcard.
    if domain.startswith("*."):
        domain = domain[2:]

    return domain


def is_valid_domain(domain: str) -> bool:
    if not domain:
        return False

    if len(domain) > 253:
        return False

    if "*" in domain:
        return False

    if "/" in domain:
        return False

    if ":" in domain:
        return False

    if "_" in domain:
        return False

    if domain.startswith("-") or domain.endswith("-"):
        return False

    if "." not in domain:
        return False

    pattern = r"^[a-z0-9.-]+\.[a-z]{2,}$"
    return re.match(pattern, domain) is not None


def extract_domain_from_url(text: str) -> str | None:
    text = text.strip()

    if text.startswith("http://") or text.startswith("https://"):
        parsed = urlparse(text)
        return parsed.hostname

    if text.startswith("|http://") or text.startswith("|https://"):
        text = text[1:]
        parsed = urlparse(text)
        return parsed.hostname

    return None


def parse_gfwlist_line(line: str):
    line = line.strip()

    if not line:
        return []

    # Comments and metadata.
    if line.startswith("!") or line.startswith("["):
        return []

    # Whitelist rules.
    if line.startswith("@@"):
        return []

    # Element hiding / CSS rules.
    if "##" in line or "#@#" in line:
        return []

    # Regex-like rules are hard to convert safely.
    if line.startswith("/") and line.endswith("/"):
        return []

    # Remove options after "$".
    if "$" in line:
        line = line.split("$", 1)[0].strip()

    results = []

    # Example: ||google.com^
    if line.startswith("||"):
        domain = line[2:]
        domain = domain.split("^", 1)[0]
        domain = domain.split("/", 1)[0]
        domain = normalize_domain(domain)
        if is_valid_domain(domain):
            results.append(("DOMAIN-SUFFIX", domain))
        return results

    # Example: |https://example.com/path
    domain_from_url = extract_domain_from_url(line)
    if domain_from_url:
        domain = normalize_domain(domain_from_url)
        if is_valid_domain(domain):
            results.append(("DOMAIN-SUFFIX", domain))
        return results

    # Example: .google.com
    if line.startswith("."):
        domain = normalize_domain(line)
        if is_valid_domain(domain):
            results.append(("DOMAIN-SUFFIX", domain))
        return results

    # Example: *://*.example.com/*
    wildcard_domain = re.search(r"\*\.(?P<domain>[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", line)
    if wildcard_domain:
        domain = normalize_domain(wildcard_domain.group("domain"))
        if is_valid_domain(domain):
            results.append(("DOMAIN-SUFFIX", domain))
        return results

    # Example: https://example.com/path without leading |
    if line.startswith("http://") or line.startswith("https://"):
        parsed = urlparse(line)
        domain = normalize_domain(parsed.hostname or "")
        if is_valid_domain(domain):
            results.append(("DOMAIN-SUFFIX", domain))
        return results

    # Remove common adblock separators.
    simple = line
    simple = simple.replace("^", "")
    simple = simple.replace("*", "")
    simple = simple.strip("|")
    simple = simple.split("/", 1)[0]
    simple = normalize_domain(simple)

    if is_valid_domain(simple):
        results.append(("DOMAIN-SUFFIX", simple))
        return results

    # Very conservative keyword fallback.
    # Only keep clean ASCII keywords that are not too broad.
    keyword = line.strip("*|^/")
    if re.match(r"^[a-zA-Z0-9-]{4,40}$", keyword):
        broad_blocklist = {
            "google",
            "youtube",
            "facebook",
            "twitter",
            "github",
            "apple",
            "cloud",
            "login",
            "mail",
            "video",
            "image",
            "static",
            "download",
            "update",
        }
        if keyword.lower() not in broad_blocklist:
            results.append(("DOMAIN-KEYWORD", keyword.lower()))

    return results


def main():
    if len(sys.argv) != 3:
        print("Usage: python convert_gfwlist.py <input_gfwlist_b64> <output_clash_list>")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = Path(sys.argv[2])

    decoded = decode_gfwlist(input_path)

    rules = set()

    for line in decoded.splitlines():
        parsed_rules = parse_gfwlist_line(line)
        for rule_type, value in parsed_rules:
            rules.add((rule_type, value))

    # Extra commonly needed domains.
    extra_domains = [
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "googlevideo.com",
        "youtube.com",
        "ytimg.com",
        "youtu.be",
        "facebook.com",
        "fbcdn.net",
        "instagram.com",
        "twitter.com",
        "x.com",
        "github.com",
        "githubusercontent.com",
        "wikipedia.org",
        "wikimedia.org",
        "telegram.org",
        "t.me",
        "tdesktop.com",
        "openai.com",
        "chatgpt.com",
        "anthropic.com",
        "claude.ai",
    ]

    for domain in extra_domains:
        rules.add(("DOMAIN-SUFFIX", domain))

    sorted_rules = sorted(rules, key=lambda item: (item[0], item[1]))

    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8", newline="\n") as f:
        f.write("# GFWList converted for Clash / FlClash\n")
        f.write("# Source: https://cdn.jsdelivr.net/gh/gfwlist/gfwlist@master/gfwlist.txt\n")
        f.write("# Generated by GitHub Actions\n")
        f.write("\n")

        for rule_type, value in sorted_rules:
            f.write(f"{rule_type},{value}\n")

    print(f"Generated {len(sorted_rules)} rules -> {output_path}")


if __name__ == "__main__":
    main()
