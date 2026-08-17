import ipaddress
import math
import re
import socket
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import numpy as np
import requests
from bs4 import BeautifulSoup

try:
    import tldextract
except ImportError:
    tldextract = None

try:
    import whois
except ImportError:
    whois = None

# FIX: cap how long WHOIS lookups can hang. Hosting platforms (e.g. Render)
# often throttle or block outbound WHOIS (port 43); without a timeout, a
# slow/blocked lookup silently degrades every legitimate old domain's
# domain_age/whois_registered_domain features to 0 (a "brand-new domain"
# signal), which the model reads as suspicious.
socket.setdefaulttimeout(6)

FEATURE_NAMES = [
    'length_url','length_hostname','ip','nb_dots','nb_hyphens','nb_at','nb_qm','nb_and','nb_or','nb_eq','nb_underscore','nb_tilde','nb_percent','nb_slash','nb_star','nb_colon','nb_comma','nb_semicolumn','nb_dollar','nb_space','nb_www','nb_com','nb_dslash','http_in_path','https_token','ratio_digits_url','ratio_digits_host','punycode','port','tld_in_path','tld_in_subdomain','abnormal_subdomain','nb_subdomains','prefix_suffix','random_domain','shortening_service','path_extension','nb_redirection','nb_external_redirection','length_words_raw','char_repeat','shortest_words_raw','shortest_word_host','shortest_word_path','longest_words_raw','longest_word_host','longest_word_path','avg_words_raw','avg_word_host','avg_word_path','phish_hints','domain_in_brand','brand_in_subdomain','brand_in_path','suspecious_tld','statistical_report','nb_hyperlinks','ratio_intHyperlinks','ratio_extHyperlinks','ratio_nullHyperlinks','nb_extCSS','ratio_intRedirection','ratio_extRedirection','ratio_intErrors','ratio_extErrors','login_form','external_favicon','links_in_tags','submit_email','ratio_intMedia','ratio_extMedia','sfh','iframe','popup_window','safe_anchor','onmouseover','right_clic','empty_title','domain_in_title','domain_with_copyright','whois_registered_domain','domain_registration_length','domain_age','web_traffic','dns_record','google_index','page_rank'
]

PHISH_HINTS = {'login','signin','verify','secure','account','update','confirm','banking','password','credential','wallet','invoice','payment','recover','unlock','support'}
BRANDS = {'google','microsoft','apple','amazon','paypal','facebook','instagram','netflix','whatsapp','linkedin','github','dropbox','adobe','bank'}
SHORTENERS = {'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly','rebrand.ly','cutt.ly','shorturl.at','tiny.cc'}
SUSPICIOUS_TLDS = {'zip','mov','top','xyz','click','link','work','gq','tk','ml','cf','ga','rest','fit','country','kim','science','party','stream','download','xin','racing','review','men','loan','date','faith','accountant'}
SAFE_SCHEMES = {'http','https'}
USER_AGENT = 'PhishGuard-Academic-Scanner/1.0'

# FIX: registrable domains that are legitimate, widely-used infrastructure
# (CDNs, asset hosts, auth providers). Large real sites routinely load
# scripts, images, and fonts from these — that pattern got misread by the
# model as "resources hosted on suspicious external domains," which is why
# CDN-heavy pages (e.g. youtube.com pulling from ytimg.com/gstatic.com)
# scored disproportionately high. Treating these as internal-equivalent for
# link/media/CSS/favicon ratio features removes that bias without touching
# the model itself.
TRUSTED_INFRASTRUCTURE_DOMAINS = {
    'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'ytimg.com',
    'doubleclick.net', 'googlesyndication.com', 'googletagmanager.com',
    'googleapis.com', 'gvt1.com', 'akamaized.net', 'akamaihd.net',
    'cloudflare.com', 'cloudflareinsights.com', 'cloudfront.net',
    'fastly.net', 'jsdelivr.net', 'unpkg.com', 'bootstrapcdn.com',
    'fbcdn.net', 'facebook.com', 'twimg.com', 'licdn.com',
    'azureedge.net', 'msftauth.net', 'msauth.net', 'live.com',
    'office.com', 'windows.net', 'amazonaws.com', 'ampproject.org',
}


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        raise ValueError('Please enter a URL.')
    if '://' not in url:
        url = 'https://' + url
    parsed = urlparse(url)
    if parsed.scheme.lower() not in SAFE_SCHEMES or not parsed.hostname:
        raise ValueError('Enter a valid HTTP or HTTPS website URL.')
    return url


def _is_public_host(hostname: str) -> bool:
    try:
        addresses = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return False
    for item in addresses:
        ip = ipaddress.ip_address(item[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            return False
    return True


def _domain_parts(hostname: str):
    hostname = (hostname or '').lower().strip('.')
    if tldextract:
        ext = tldextract.extract(hostname)
        registered = '.'.join(x for x in [ext.domain, ext.suffix] if x)
        return ext.subdomain, ext.domain, ext.suffix, registered
    bits = hostname.split('.')
    suffix = bits[-1] if len(bits) > 1 else ''
    domain = bits[-2] if len(bits) > 1 else bits[0]
    sub = '.'.join(bits[:-2]) if len(bits) > 2 else ''
    return sub, domain, suffix, '.'.join(x for x in [domain, suffix] if x)


def _words(value: str):
    return [w for w in re.split(r'[^A-Za-z0-9]+', value or '') if w]


def _safe_ratio(a, b):
    return float(a) / float(b) if b else 0.0


def _same_domain(target: str, base_registered: str):
    """FIX: now also treats known trusted infrastructure domains (CDNs,
    asset hosts, auth providers) as internal-equivalent, so legitimate
    multi-domain sites aren't penalised for using them."""
    try:
        host = urlparse(target).hostname or ''
        target_registered = _domain_parts(host)[3]
        if target_registered == base_registered:
            return True
        return target_registered in TRUSTED_INFRASTRUCTURE_DOMAINS
    except Exception:
        return False


def _dates(value):
    if value is None:
        return []
    values = value if isinstance(value, (list, tuple)) else [value]
    out = []
    for v in values:
        if isinstance(v, datetime):
            out.append(v if v.tzinfo else v.replace(tzinfo=timezone.utc))
    return out


def extract_features(raw_url: str, fetch_page: bool = True):
    url = normalize_url(raw_url)
    p = urlparse(url)
    host = (p.hostname or '').lower()
    subdomain, domain, tld, registered = _domain_parts(host)
    path_and_query = (p.path or '') + ('?' + p.query if p.query else '')

    f = {name: 0.0 for name in FEATURE_NAMES}
    f.update({
        'length_url': len(url), 'length_hostname': len(host),
        'ip': int(_looks_like_ip(host)), 'nb_dots': url.count('.'), 'nb_hyphens': url.count('-'),
        'nb_at': url.count('@'), 'nb_qm': url.count('?'), 'nb_and': url.count('&'), 'nb_or': url.count('|'),
        'nb_eq': url.count('='), 'nb_underscore': url.count('_'), 'nb_tilde': url.count('~'),
        'nb_percent': url.count('%'), 'nb_slash': url.count('/'), 'nb_star': url.count('*'),
        'nb_colon': url.count(':'), 'nb_comma': url.count(','), 'nb_semicolumn': url.count(';'),
        'nb_dollar': url.count('$'), 'nb_space': len(re.findall(r'\s|%20', url, re.I)),
        'nb_www': url.lower().count('www'), 'nb_com': url.lower().count('.com'), 'nb_dslash': path_and_query.count('//'),
        'http_in_path': int('http' in path_and_query.lower()),
        'https_token': int('https' in subdomain.lower() or 'https' in domain.lower()),
        'ratio_digits_url': _safe_ratio(sum(c.isdigit() for c in url), len(url)),
        'ratio_digits_host': _safe_ratio(sum(c.isdigit() for c in host), len(host)),
        'punycode': int('xn--' in host), 'port': int(p.port is not None),
        'tld_in_path': int(bool(tld and re.search(rf'(^|[./_-]){re.escape(tld)}([./_-]|$)', p.path.lower()))),
        'tld_in_subdomain': int(bool(tld and tld in subdomain.split('.'))),
        'abnormal_subdomain': int(bool(subdomain and (subdomain.startswith('www-') or len(subdomain.split('.')) > 3))),
        'nb_subdomains': max(0, len([x for x in subdomain.split('.') if x])),
        'prefix_suffix': int('-' in domain),
        'random_domain': int(_randomness(domain) > 0.68 and len(domain) >= 8),
        'shortening_service': int(registered in SHORTENERS),
        'path_extension': int(bool(re.search(r'\.(exe|zip|rar|scr|js|php|html?)$', p.path, re.I))),
    })

    raw_words = _words(url)
    host_words = _words(host)
    path_words = _words(path_and_query)
    _word_stats(f, raw_words, host_words, path_words)
    lowered_words = {w.lower() for w in raw_words}
    f['phish_hints'] = sum(1 for hint in PHISH_HINTS if hint in lowered_words or hint in url.lower())
    f['domain_in_brand'] = int(domain in BRANDS)
    f['brand_in_subdomain'] = int(any(b in subdomain.lower() for b in BRANDS if b != domain))
    f['brand_in_path'] = int(any(b in p.path.lower() for b in BRANDS if b != domain))
    f['suspecious_tld'] = int(tld in SUSPICIOUS_TLDS)
    f['statistical_report'] = int(_looks_like_ip(host) or registered in {'at.ua','usa.cc','baltazarpresentes.com.br','pe.hu','esy.es'} )

    warnings = []
    page_info = {'fetched': False, 'status_code': None, 'title': '', 'final_url': url}
    if fetch_page:
        if not _is_public_host(host):
            warnings.append('The host could not be resolved publicly or points to a protected network address, so its webpage was not fetched.')
        else:
            try:
                response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=8, allow_redirects=True, stream=True)
                response.raise_for_status()
                content_type = response.headers.get('content-type','').lower()
                if 'text/html' not in content_type:
                    warnings.append('The URL did not return an HTML page; webpage-based features use neutral values.')
                else:
                    content = response.raw.read(1_500_000, decode_content=True)
                    html = content.decode(response.encoding or 'utf-8', errors='replace')
                    _html_features(f, url, registered, html, response.url, len(response.history))
                    page_info.update({'fetched': True, 'status_code': response.status_code, 'final_url': response.url, 'title': BeautifulSoup(html, 'html.parser').title.get_text(' ', strip=True) if BeautifulSoup(html, 'html.parser').title else ''})
            except requests.RequestException:
                warnings.append('The page could not be fetched safely; URL features were still analysed.')

    _domain_features(f, registered, warnings)
    values = np.array([float(f.get(name, 0.0)) for name in FEATURE_NAMES], dtype=float)
    details = {
        'normalized_url': url, 'hostname': host, 'registered_domain': registered,
        'uses_https': p.scheme.lower() == 'https', 'url_length': len(url), 'dots': url.count('.'),
        'hyphens': url.count('-'), 'subdomains': int(f['nb_subdomains']), 'ip_address': bool(f['ip']),
        'phishing_terms': int(f['phish_hints']), 'page': page_info, 'warnings': warnings,
    }
    return values, f, details


def _looks_like_ip(host):
    try:
        ipaddress.ip_address(host.strip('[]'))
        return True
    except ValueError:
        return bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', host or ''))


def _randomness(text):
    if not text:
        return 0.0
    counts = Counter(text)
    entropy = -sum((n/len(text))*math.log2(n/len(text)) for n in counts.values())
    return entropy / math.log2(max(2, len(set(text))))


def _word_stats(f, raw, host, path):
    f['length_words_raw'] = len(raw)
    repeated = re.findall(r'(.)\1{2,}', ''.join(raw).lower())
    f['char_repeat'] = len(repeated)
    for words, shortest, longest, avg in [
        (raw,'shortest_words_raw','longest_words_raw','avg_words_raw'),
        (host,'shortest_word_host','longest_word_host','avg_word_host'),
        (path,'shortest_word_path','longest_word_path','avg_word_path')]:
        lengths = [len(w) for w in words]
        f[shortest] = min(lengths) if lengths else 0
        f[longest] = max(lengths) if lengths else 0
        f[avg] = sum(lengths)/len(lengths) if lengths else 0


def _html_features(f, original_url, registered, html, final_url, redirect_count):
    soup = BeautifulSoup(html, 'html.parser')
    base = final_url or original_url
    f['nb_redirection'] = redirect_count
    f['nb_external_redirection'] = int(not _same_domain(base, registered))

    links = []
    null_links = 0
    for tag, attr in [('a','href'),('link','href'),('script','src'),('img','src'),('form','action'),('video','src'),('audio','src'),('source','src')]:
        for node in soup.find_all(tag):
            value = (node.get(attr) or '').strip()
            if not value or value.lower().startswith(('javascript:','#','about:blank')):
                null_links += 1
            else:
                links.append((tag, urljoin(base, value)))
    internal = [u for _,u in links if _same_domain(u, registered)]
    external = [u for _,u in links if not _same_domain(u, registered)]
    total = len(links) + null_links
    f['nb_hyperlinks'] = len(links)
    f['ratio_intHyperlinks'] = 100 * _safe_ratio(len(internal), total)
    f['ratio_extHyperlinks'] = 100 * _safe_ratio(len(external), total)
    f['ratio_nullHyperlinks'] = 100 * _safe_ratio(null_links, total)
    f['nb_extCSS'] = sum(1 for x in soup.find_all('link', href=True) if 'stylesheet' in [r.lower() for r in (x.get('rel') or [])] and not _same_domain(urljoin(base,x['href']),registered))

    forms = soup.find_all('form')
    f['login_form'] = int(any(form.find('input', {'type': re.compile('password', re.I)}) for form in forms))
    f['submit_email'] = int(any((form.get('action') or '').lower().startswith('mailto:') for form in forms) or 'mailto:' in html.lower())
    f['sfh'] = int(any(not (form.get('action') or '').strip() or (form.get('action') or '').strip().lower() == 'about:blank' for form in forms))
    favicon = soup.find('link', rel=lambda v: v and 'icon' in ' '.join(v).lower() if isinstance(v,list) else v and 'icon' in v.lower())
    f['external_favicon'] = int(bool(favicon and favicon.get('href') and not _same_domain(urljoin(base,favicon['href']),registered)))

    tag_urls = []
    for tag, attr in [('meta','content'),('script','src'),('link','href')]:
        for node in soup.find_all(tag):
            val = node.get(attr)
            if val and ('/' in val or val.startswith('http')):
                tag_urls.append(urljoin(base,val))
    f['links_in_tags'] = 100 * _safe_ratio(sum(_same_domain(u, registered) for u in tag_urls), len(tag_urls))
    media = [u for tag,u in links if tag in {'img','video','audio','source'}]
    f['ratio_intMedia'] = 100 * _safe_ratio(sum(_same_domain(u,registered) for u in media),len(media))
    f['ratio_extMedia'] = 100 * _safe_ratio(sum(not _same_domain(u,registered) for u in media),len(media))
    anchors = [urljoin(base,(a.get('href') or '')) for a in soup.find_all('a') if (a.get('href') or '').strip()]
    unsafe = sum(1 for u in anchors if not _same_domain(u,registered) or u.lower().startswith(('javascript:','#')))
    f['safe_anchor'] = 100 * _safe_ratio(unsafe, len(anchors))
    f['iframe'] = int(bool(soup.find(['iframe','frame'])))
    low = html.lower()
    f['popup_window'] = int('window.open(' in low)
    f['onmouseover'] = int('onmouseover=' in low)
    f['right_clic'] = int('contextmenu' in low or 'event.button==2' in low)
    title = soup.title.get_text(' ',strip=True) if soup.title else ''
    f['empty_title'] = int(not title)
    f['domain_in_title'] = int(bool(registered and registered.split('.')[0] in title.lower()))
    copyright_text = ' '.join(soup.stripped_strings).lower()
    f['domain_with_copyright'] = int(bool(('©' in copyright_text or 'copyright' in copyright_text) and registered.split('.')[0] in copyright_text))


def _domain_features(f, registered, warnings):
    try:
        socket.getaddrinfo(registered, None)
        f['dns_record'] = 1
    except Exception:
        f['dns_record'] = 0
    if whois and registered:
        try:
            data = whois.whois(registered)
            created = _dates(getattr(data,'creation_date',None))
            expires = _dates(getattr(data,'expiration_date',None))
            now = datetime.now(timezone.utc)
            f['whois_registered_domain'] = int(bool(created or expires or getattr(data,'domain_name',None)))
            if created:
                f['domain_age'] = max(0, int((now - min(created)).days))
            if created and expires:
                f['domain_registration_length'] = max(0, int((max(expires)-min(created)).days))
        except Exception:
            # FIX: previously this only added a warning; the underlying
            # features stayed at their zero-initialized default, which
            # reads as "brand-new, unregistered domain" — a phishing
            # signal — for any site whose WHOIS lookup merely timed out
            # (common on hosts that block outbound port 43). We now surface
            # this more clearly in the warning so it's visible in the UI.
            warnings.append('WHOIS lookup failed or timed out (this can happen on hosts that block outbound WHOIS); domain-age features use neutral defaults and should not be treated as evidence the domain is new.')
    elif not whois:
        warnings.append('The whois package is not installed on the server; domain-age features use neutral defaults.')

    # REVERTED: an earlier patch changed these from 0 to 1, guessing that
    # 0 = "unranked/suspicious" in the training data. Testing showed the
    # opposite: flipping to 1 made known-legitimate sites score *higher*
    # for phishing (github.com went to 100%), meaning this model's training
    # data does not follow that convention, or these columns carry little
    # real signal either way and 1 is simply out-of-distribution for them.
    # Reverted to the original hardcoded 0 pending an empirical test — see
    # probe_features.py, which measures the actual effect of 0 vs 1 on
    # THIS model directly instead of assuming a convention.
    f['web_traffic'] = 0
    f['google_index'] = 0
    f['page_rank'] = 0