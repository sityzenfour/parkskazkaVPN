#!/usr/bin/env python3
"""Print an allowlisted REALITY report without changing Xray or contacting hosts."""

import argparse
import base64
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path


def running_config():
    candidates = []
    for directory in Path('/proc').iterdir():
        if not directory.name.isdigit():
            continue
        try:
            arguments = directory.joinpath('cmdline').read_bytes().split(b'\0')
            arguments = [item.decode() for item in arguments if item]
            if not arguments or not Path(arguments[0]).name.startswith('xray'):
                continue
            paths = []
            for index, argument in enumerate(arguments):
                if argument in ('-c', '-config', '--config'):
                    paths.append(arguments[index + 1])
                elif argument.startswith(('-c=', '-config=', '--config=')):
                    paths.append(argument.split('=', 1)[1])
            if len(paths) != 1:
                raise RuntimeError('Expected one Xray configuration file. Use --config with the verified active file.')
            config_path = Path(paths[0])
            if not config_path.is_absolute():
                config_path = directory.joinpath('cwd').resolve() / config_path
            candidates.append((config_path, str(directory.joinpath('exe').resolve()), int(directory.name)))
        except (OSError, UnicodeError, IndexError):
            continue
    if len(candidates) != 1:
        raise RuntimeError('Could not identify exactly one running Xray process. Specify --config with the verified active file.')
    return candidates[0]


def compare_public_key(private_key, expected_public_key):
    if not expected_public_key:
        return 'not_requested'
    if not private_key:
        return 'private_key_missing'
    openssl = shutil.which('openssl')
    if not openssl:
        return 'not_checked_openssl_missing'
    try:
        raw = base64.urlsafe_b64decode(private_key + '=' * (-len(private_key) % 4))
        if len(raw) != 32:
            return 'invalid_private_key_length'
        # X25519 PKCS#8. Private bytes travel only through the local stdin pipe.
        der = bytes.fromhex('302e020100300506032b656e04220420') + raw
        result = subprocess.run(
            [openssl, 'pkey', '-inform', 'DER', '-pubout', '-outform', 'DER'],
            input=der, capture_output=True, timeout=5, check=True,
        )
        prefix = bytes.fromhex('302a300506032b656e032100')
        if len(result.stdout) != len(prefix) + 32 or not result.stdout.startswith(prefix):
            return 'not_checked_unexpected_openssl_output'
        public_key = base64.urlsafe_b64encode(result.stdout[-32:]).decode().rstrip('=')
        return public_key == expected_public_key.rstrip('=')
    except (ValueError, TypeError, subprocess.SubprocessError, OSError):
        return 'not_checked_key_derivation_failed'


def reality_report(config, expected_sni, expected_public_key):
    reports = []
    for inbound in config.get('inbounds', []):
        stream = inbound.get('streamSettings') or {}
        if stream.get('security') != 'reality':
            continue
        reality = stream.get('realitySettings') or {}
        xhttp = stream.get('xhttpSettings') or {}
        extra = xhttp.get('extra') or {}
        if not isinstance(extra, dict):
            extra = {}
        names = reality.get('serverNames') or []
        short_ids = reality.get('shortIds') or []
        settings = inbound.get('settings') or {}
        fields = ('xPaddingBytes', 'xPaddingObfsMode', 'xPaddingPlacement',
                  'xPaddingMethod', 'uplinkHTTPMethod', 'sessionIDPlacement', 'seqPlacement')
        report = {
            'tag': inbound.get('tag'),
            'listen': inbound.get('listen'),
            'port': inbound.get('port'),
            'protocol': inbound.get('protocol'),
            'network': stream.get('network'),
            'security': stream.get('security'),
            'target': reality.get('target', reality.get('dest')),
            'serverNames': names,
            'providedClientSniAllowed': expected_sni in names if expected_sni else 'not_requested',
            'providedClientPublicKeyMatches': compare_public_key(reality.get('privateKey'), expected_public_key),
            'privateKeyPresent': bool(reality.get('privateKey')),
            'shortIdCount': len(short_ids),
            'emptyShortIdAllowed': '' in short_ids,
            'shortIdLengths': sorted(set(len(value) for value in short_ids)),
            'shortIdsHaveValidFormat': all(re.fullmatch(r'(?:[0-9a-fA-F]{2}){0,8}', value) is not None for value in short_ids),
            'minClientVer': reality.get('minClientVer'),
            'maxClientVer': reality.get('maxClientVer'),
            'maxTimeDiff': reality.get('maxTimeDiff'),
            'xver': reality.get('xver'),
            'show': reality.get('show', False),
            'fallbackLimits': {
                direction: {key: (reality.get(direction) or {}).get(key, 0)
                            for key in ('afterBytes', 'bytesPerSec', 'burstBytesPerSec')}
                for direction in ('limitFallbackUpload', 'limitFallbackDownload')
            },
            'clientCount': len(settings.get('clients') or []),
            'sniffing': {key: (inbound.get('sniffing') or {}).get(key)
                         for key in ('enabled', 'destOverride', 'routeOnly')},
            'xhttp': {key: xhttp.get(key) for key in ('host', 'path', 'mode')},
        }
        report['xhttp'].update({key: extra.get(key, xhttp.get(key)) for key in fields})
        reports.append(report)
    return reports


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path)
    parser.add_argument('--client-sni')
    parser.add_argument('--client-public-key')
    args = parser.parse_args()
    if args.config:
        config_path, executable, pid = args.config, None, None
        source = 'explicit_file_path'
    else:
        config_path, executable, pid = running_config()
        source = 'running_process_command_line'
    try:
        config = json.loads(config_path.read_text(encoding='utf-8-sig'))
    except (OSError, ValueError):
        raise RuntimeError('Cannot read this config as JSON. No configuration contents were printed.') from None
    if not isinstance(config, dict):
        raise RuntimeError('Expected one JSON configuration object.')
    report = {
        'configSource': source, 'configFile': str(config_path),
        'xrayExecutable': executable, 'pid': pid,
        'realityInbounds': reality_report(config, args.client_sni, args.client_public_key),
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, ValueError, TypeError) as error:
        # Never dump the source configuration or include private-key values.
        print('Audit could not complete. Check the active config path and run as root.', file=sys.stderr)
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        sys.exit(1)
