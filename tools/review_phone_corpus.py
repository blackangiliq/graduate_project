"""Verify retained evidence coordinates and publish credential-free corpus counts.

Requires the independent reference and audit_phone_apps.py artifacts. Full candidate
values are written only to --details under the caller-selected local audit folder;
--output contains hashes/counts and APK member names, never extracted values.
"""
import argparse
import collections
import base64
from datetime import datetime, timezone
import gzip
import hashlib
import html
import json
from pathlib import Path
import re
import sys

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tools.compare_phone_audit import pem_key, url_key

EXPECTED = {'literal_service_or_web_address', 'local_development_address', 'runtime_address_template'}
TARGET_RESOURCE = re.compile(r'(?i)(?:idp_.*api_token|appmetrica_.*token|webengage_.*token|facebook_client_token|com_braze_api_key)$')


def matches_source(value, place, sources, multiline=False):
    sf = sources.get(place.get('file', ''))
    number = place.get('line', 0)
    if sf is None or not isinstance(number, int) or not 1 <= number <= len(sf['lines']):
        return 'invalid_location'
    line = sf['lines'][number - 1]
    if value in line:
        return 'literal_exact'
    if value in html.unescape(line):
        return 'xml_entity_equivalent'
    if multiline and pem_key(value):
        block = '\n'.join(sf['lines'][number - 1:number + 200])
        if pem_key(value) == pem_key(block):
            return 'pem_body_equivalent'
    return 'needs_review'


def phase(app, name, root, baseline):
    folder = root / name
    report_file = folder / (app['name'] + '.report.json')
    if not all((folder / (app['name'] + suffix)).is_file() for suffix in
               ('.report.json', '.summary.json', '.hits.json', '.sources.json.gz')):
        return None, None
    report = json.loads(report_file.read_text(encoding='utf8'))
    summary = json.loads((folder / (app['name'] + '.summary.json')).read_text(encoding='utf8'))
    hits = json.loads((folder / (app['name'] + '.hits.json')).read_text(encoding='utf8'))
    with gzip.open(folder / (app['name'] + '.sources.json.gz'), 'rt', encoding='utf8') as handle:
        sources = json.load(handle)
    apis = report['app']['apis']
    derived_checks = collections.Counter()
    derived_issues = []
    for rel, source in sources.items():
        if source.get('origin') != 'decoded_literal':
            continue
        provenance = source.get('derivation', {})
        try:
            parent = sources[provenance['source_file']]
            text = parent['lines'][provenance['source_line'] - 1]
            encoded = text[provenance['source_column'] - 1:provenance['source_end_column'] - 1]
            assert hashlib.sha256(encoded.encode()).hexdigest() == provenance['encoded_sha256']
            assert provenance['depth'] in (1, 2)
            decoded = encoded
            for _ in range(provenance['depth']):
                raw = base64.b64decode(decoded + '=' * (-len(decoded) % 4), altchars=b'-_', validate=True)
                decoded = raw.decode('utf8')
            assert hashlib.sha256(decoded.encode('utf8')).hexdigest() == provenance['decoded_sha256']
            assert decoded.splitlines() == source['lines']
            derived_checks['independent_base64_roundtrip_exact'] += 1
        except (KeyError, IndexError, UnicodeError, ValueError, AssertionError) as exc:
            derived_checks['needs_review'] += 1
            derived_issues.append({'file': rel, 'error': type(exc).__name__, 'derivation': provenance})
    values = {hit['value'] for hit in hits}
    external_path = root / 'gitleaks' / app['name'] / 'comparison.json'
    external = json.loads(external_path.read_text(encoding='utf8')) if external_path.is_file() else []
    encoded_provider_reference = [item for item in external
        if item.get('rule') == 'gcp-api-key' and 'decoded:base64' in item.get('tags', [])]
    addresses = {url_key(item['url']) for item in apis.get('endpoints', [])}
    expected = [key for key in app['keys'] if key['status'] == 'format_candidate_not_remotely_validated']
    candidate_urls = [item for item in app['urls'] if item.get('category') in EXPECTED]
    missing_keys = [item for item in expected if item['value'] not in values]
    missing_urls = [item for item in candidate_urls if url_key(item['value']) not in addresses]
    expected_pems = {pem_key(item['value']) for item in app.get('pem_blocks', [])} - {None}
    found_pems = {pem_key(value) for value in values} - {None}
    source_checks = {}
    issues = []
    for bucket, items, field in (('secret_hits', hits, 'value'), ('keys', apis.get('keys', []), 'value'),
                                ('endpoints', apis.get('endpoints', []), 'url'),
                                ('config', apis.get('config', []), 'value')):
        counts = collections.Counter()
        for item in items:
            for place in item.get('locations', [item] if bucket == 'secret_hits' else []):
                outcome = matches_source(item[field], place, sources, multiline=bucket in ('secret_hits', 'keys'))
                counts[outcome] += 1
                if outcome not in ('literal_exact', 'xml_entity_equivalent', 'pem_body_equivalent'):
                    issues.append({'bucket': bucket, 'value': item[field], 'location': place, 'outcome': outcome})
        source_checks[bucket] = dict(counts)
    chosen_config = [item for item in app['named_resources'] if TARGET_RESOURCE.search(item['name'])]
    config_values = {item['value'] for item in apis.get('config', [])}
    template_reference = [u for u in candidate_urls if u.get('category') == 'runtime_address_template']
    template_matches = sum(url_key(u['value']) in addresses for u in template_reference)
    baseline_file = baseline / name / (app['name'] + '.summary.json') if baseline else None
    old_summary = json.loads(baseline_file.read_text(encoding='utf8')) if baseline_file and baseline_file.is_file() else {}
    java = report['app'].get('java_decompilation', {})
    safe = {
        'status': summary['status'], 'archive_scan_id': summary.get('scan_id'),
        'scan_identity': {key: summary.get('identity', {}).get(key) for key in
                          ('schema', 'detectors_sha256', 'apk_tools', 'ml', 'llm', 'feedback')},
        'files': summary['files'], 'findings': summary['findings'],
        'keys': len(apis.get('keys', [])), 'endpoints': len(addresses),
        'displayed_address_rows': len(apis.get('endpoints', [])), 'config': len(config_values),
        'api_calls': len(apis.get('calls', [])), 'api_paths': len(apis.get('paths', [])),
        'baseline_counts': {field: old_summary.get(field, 0) for field in ('files', 'findings', 'keys', 'endpoints', 'calls', 'paths')} if old_summary else None,
        'provider_format_reference': len(expected), 'provider_format_matches': len(expected) - len(missing_keys),
        'external_encoded_provider_reference': len(encoded_provider_reference),
        'external_encoded_provider_matches': sum(item['value'] in values for item in encoded_provider_reference),
        'complete_pem_reference': len(expected_pems), 'complete_pem_matches': len(expected_pems & found_pems),
        'candidate_address_reference': len(candidate_urls), 'candidate_address_matches': len(candidate_urls) - len(missing_urls),
        'template_reference': len(template_reference), 'template_matches': template_matches,
        'displayed_url_templates': sum(bool(e.get('requires_runtime_resolution')) for e in apis.get('endpoints', [])),
        'manually_selected_sdk_configuration_reference': len(chosen_config),
        'manually_selected_sdk_configuration_matches': sum(item['value'] in config_values for item in chosen_config),
        'configuration_classifications': dict(collections.Counter(item.get('classification', 'known_service_configuration') for item in apis.get('config', []))),
        'source_location_checks': source_checks, 'source_location_issues': len(issues),
        'derived_evidence_source_checks': dict(derived_checks),
        'derived_evidence_source_issues': len(derived_issues),
        'base64_coverage': report.get('app', {}).get('encoded_literal_coverage', {}),
        'inventory_limits': apis.get('truncated', {}),
        'complex_resources': report['app'].get('complex_resources', {}),
        'native_string_coverage': {k: report['app'].get('native_string_coverage', {}).get(k)
                                  for k in ('abis', 'libraries_present', 'scope')},
        'native_libraries_read': len(report['app'].get('native_string_coverage', {}).get('libraries_read', [])),
        'native_libraries_metadata_only': len(report['app'].get('native_string_coverage', {}).get('metadata_only', [])),
        'native_libraries_omitted': len(report['app'].get('native_string_coverage', {}).get('libraries_omitted', [])),
        'members': len(report['app'].get('apk_members', [])),
        'member_statuses': dict(collections.Counter(item.get('status') for item in report['app'].get('apk_members', []))),
        'java_decompiled_files': java.get('loaded_files', 0),
        'java_decompilation_limits': {key: java.get(key) for key in ('file_limit', 'time_limit_seconds')},
        'java_decompilation_cache_reused': 'earlier scan' in java.get('status', ''),
        'java_decompilation_original_status_available': 'unavailable' not in java.get('status', ''),
        'analysis_coverage': {key: value for key, value in report['app'].get('analysis_coverage', {}).items()
                              if isinstance(value, (int, float, bool))},
    }
    detail = {'missing_provider_formats': missing_keys, 'missing_candidate_addresses': missing_urls,
              'source_location_issues': issues, 'derived_source_issues': derived_issues, 'reviewed_configuration': [
                  {'name': item['name'], 'value': item['value'], 'found': item['value'] in config_values,
                   'locations': [e.get('locations') for e in apis.get('config', []) if e['value'] == item['value']]}
                  for item in chosen_config]}
    return safe, detail


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=Path, help="Local audit directory containing reference.json and phase directories")
    parser.add_argument("--baseline", type=Path, help="Optional previous audit directory for count and input-hash comparison")
    parser.add_argument("--phases", nargs="+", default=["updated", "deep"])
    parser.add_argument("--output", type=Path, help="Sanitized JSON destination (default: ROOT/review_summary.json)")
    parser.add_argument("--details", type=Path, help="Private full-value details destination (default: ROOT/review_details.json)")
    args = parser.parse_args()
    reference = json.loads((args.root / "reference.json").read_text(encoding="utf8"))
    prior_file = args.baseline / "reference.json" if args.baseline else None
    previous_reference = json.loads(prior_file.read_text(encoding="utf8")) if prior_file and prior_file.is_file() else None
    out = {
        'schema_version': 1, 'reviewed_utc': datetime.now(timezone.utc).isoformat(),
        'method': 'Independent Android SDK AAPT2, direct APK bytes and DEX string-table reference; selected manifest/resource/literal review followed by exact values and retained-coordinate comparison. Not exhaustive manual code review or exploitability validation.',
        'scope': 'Provided Android app sets. Candidate addresses include documentation, templates and metadata; address match counts are not endpoint completeness or vulnerability recall.',
        'sources': reference.get('sources', []), 'apps': [],
    }
    details = {'apps': []}
    for app in reference['apps']:
        previous = next((a for a in previous_reference['apps'] if a['name'] == app['name']), None) if previous_reference else None
        hashes_same = ({(a['name'], a['sha256']) for a in app['apks']} == {(a['name'], a['sha256']) for a in previous['apks']}) if previous else None
        row = {
            'app': app['name'], 'input_apks': len(app['apks']),
            'same_input_hashes_as_previous_audit': hashes_same,
            'inputs': [{k: a[k] for k in ('name', 'size', 'sha256')} for a in app['apks']],
            'reference_entry_read_limits': len(app.get('limits', [])), 'phases': {},
        }
        detail_row = {'app': app['name'], 'phases': {}}
        for name in args.phases:
            safe, detail = phase(app, name, args.root, args.baseline)
            if safe:
                row['phases'][name] = safe
                detail_row['phases'][name] = detail
        out['apps'].append(row)
        details['apps'].append(detail_row)
    totals = {}
    numeric_fields = (
        'files', 'findings', 'keys', 'endpoints', 'displayed_address_rows', 'config',
        'api_calls', 'api_paths', 'provider_format_reference', 'provider_format_matches',
        'external_encoded_provider_reference', 'external_encoded_provider_matches',
        'complete_pem_reference', 'complete_pem_matches', 'candidate_address_reference',
        'candidate_address_matches', 'template_reference', 'template_matches',
        'manually_selected_sdk_configuration_reference', 'manually_selected_sdk_configuration_matches',
        'source_location_issues', 'derived_evidence_source_issues', 'java_decompiled_files',
    )
    for name in args.phases:
        rows = [app['phases'][name] for app in out['apps'] if name in app['phases']]
        totals[name] = {field: sum(row[field] for row in rows) for field in numeric_fields}
        totals[name]['completed_apps'] = len(rows)
    out['totals'] = totals
    verification = {
        'apps': len(out['apps']),
        'phases': collections.Counter(p for a in out['apps'] for p in a['phases']),
        'complete_requested_phases': all(len(a['phases']) == len(args.phases) for a in out['apps']),
        'location_issues': sum(p['source_location_issues'] for a in out['apps'] for p in a['phases'].values()),
        'derived_source_issues': sum(p['derived_evidence_source_issues'] for a in out['apps'] for p in a['phases'].values()),
        'input_hashes_match': all(a['same_input_hashes_as_previous_audit'] for a in out['apps']) if previous_reference else None,
    }
    out['verification'] = verification
    destination = args.output or args.root / 'review_summary.json'
    private_destination = args.details or args.root / 'review_details.json'
    if destination.resolve() == private_destination.resolve():
        parser.error('--output and --details must have different destinations')
    destination.parent.mkdir(parents=True, exist_ok=True)
    private_destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf8')
    private_destination.write_text(json.dumps(details, indent=2, ensure_ascii=False), encoding='utf8')
    print(json.dumps(verification))
    if not verification['complete_requested_phases'] or verification['location_issues'] or verification['derived_source_issues']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()
