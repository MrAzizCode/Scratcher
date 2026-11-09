"""Static coverage diagnostic. Never launches, attaches to, or modifies the input."""
import argparse
import collections
import hashlib
import json
import pathlib
import struct
import sys
import time

import numpy as np
from mcp_client import Client

ROOT = pathlib.Path('D:/Scratcher')
EXPECTED = '11a30ada177d15a9ec1c1dc30957b28b46839c9c6407e53be6138d2f12f6f2fe'


def entropy(data):
    if not len(data):
        return 0.0
    counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
    probabilities = counts[counts > 0] / len(data)
    return float(-np.sum(probabilities * np.log2(probabilities)))


def quantiles(values):
    return dict(zip(('minimum', 'p10', 'p50', 'p90', 'maximum'),
                    (float(x) for x in np.quantile(values, [0, .1, .5, .9, 1])))) if values else {}


class PE:
    def __init__(self, path):
        self.data = path.read_bytes()
        self.digest = hashlib.sha256(self.data).hexdigest()
        pe, = self.read('<I', 0x3c)
        assert self.data[pe:pe+4] == b'PE\0\0'
        count, = self.read('<H', pe+6)
        optional_size, = self.read('<H', pe+20)
        optional = pe + 24
        magic, = self.read('<H', optional)
        assert magic == 0x20b, 'This diagnostic expects PE64'
        self.base, = self.read('<Q', optional+24)
        entry_rva, = self.read('<I', optional+16)
        self.entry = self.base + entry_rva if entry_rva else 0
        self.directory_offset = optional+112
        self.sections = []
        for n in range(count):
            at = optional+optional_size+n*40
            name = self.data[at:at+8].split(b'\0')[0].decode('ascii', 'replace')
            memory, rva, size, offset = self.read('<IIII', at+8)
            flags, = self.read('<I', at+36)
            assert offset+size <= len(self.data)
            self.sections.append(dict(name=name, va=self.base+rva, size=size,
                                      offset=offset, virtual_size=memory, memory_size=max(memory, size), flags=flags))

    def read(self, fmt, offset):
        assert offset >= 0 and offset+struct.calcsize(fmt) <= len(self.data)
        return struct.unpack_from(fmt, self.data, offset)

    def section(self, va):
        return next((s for s in self.sections if s['va'] <= va < s['va']+s['size']), None)

    def offset(self, va, size=1):
        section = self.section(va)
        assert section and va+size <= section['va']+section['size'], 'Non-file-backed metadata'
        return section['offset']+va-section['va']

    def bytes(self, va, size):
        section = self.section(va)
        if not section:
            return b''
        at = self.offset(va)
        return self.data[at:at+min(size, section['va']+section['size']-va)]

    def cfg(self):
        rva, size = self.read('<II', self.directory_offset+10*8)
        assert size >= 148
        at = self.offset(self.base+rva, 148)
        table, count = self.read('<QQ', at+128)
        flags, = self.read('<I', at+144)
        stride = 4+(flags >> 28)
        table_at = self.offset(table, count*stride)
        entries = []
        for n in range(count):
            target_rva, = self.read('<I', table_at+n*stride)
            extra = self.data[table_at+n*stride+4] if stride > 4 else 0
            entries.append(dict(va=self.base+target_rva, flags=extra))
        assert all(a['va'] <= b['va'] for a, b in zip(entries, entries[1:]))
        return entries, dict(entry_count=count, stride=stride, flags=flags, table=hex(table))


def evenly(rows, count):
    if not rows:
        return []
    return [rows[i] for i in sorted(set(int(x) for x in np.linspace(0, len(rows)-1, min(count, len(rows)))))]


def write_report(result, output):
    output.mkdir(parents=True, exist_ok=True)
    (output/'diagnostics.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
    summary = result.get('code_paths', {})
    samples = result.get('sample_summary', {})
    lines = [
        '# Roblox static decoding diagnostics', '',
        f"Input SHA256: `{result['input']['sha256']}`. Input bytes remain unchanged. No Computer Use, input execution, process attachment, dump or unpacking.", '',
        'Byte entropy is descriptive. High entropy and decoding failures can indicate transformed code or non-code data, but do not establish encryption or identify a transformation.', '',
        '| Section | File-backed bytes | Declared execute | Full-section entropy bits/byte | 64 KiB window median | CFG starts |',
        '|---|---:|---|---:|---:|---:|',
    ]
    for s in result['sections']:
        lines.append(f"| {s['name']} | {s['size']} | {s['declared_execute']} | {s['entropy_bits_per_byte']:.5f} | {s['window_entropy']['p50']:.5f} | {s['cfg_starts']} |")
    lines += ['', f"Candidate scope is fixed at {result['candidate_scope_bytes']:,} original-file bytes; 70% requires {result['target_70_bytes']:,} unique supported code bytes.", '',
        f"Current bounded reachable pass decoded {summary.get('covered_bytes', 0):,} unique bytes, with {summary.get('invalid_stops', 0):,} invalid stops and {summary.get('boundary_stops', 0):,} boundary stops. These are instruction candidates, not proven source functions.", '',
        f"The deterministic metadata-start sample has {samples.get('count', 0)} listings; {samples.get('first_instruction_invalid', 0)} fail at the first instruction and {samples.get('invalid_within_32_instruction_listing', 0)} contain an invalid byte within the first 32 listing rows. Listings resynchronize by one byte after invalid opcodes, so their apparent later decoding is excluded from coverage.", '',
        f"Metadata CFG quantiles alone: {samples.get('cfg_quantiles', {})}. Independent deterministic random-offset controls: {samples.get('random_offset_controls', {})}. Random controls are diagnostics only and contribute zero coverage/seeds.", '',
        f"Full-width observed-end probes: {samples.get('observed_end_probes', {})}. An observed maximum end may belong to a different branch, so these probes are descriptive rather than guaranteed stop-address attribution.", '',
        'The full-width listing check distinguishes failures caused only by the next-start cutoff: a listing can decode a real instruction across an indexed boundary where the bounded pass cannot. Such cases are counted separately and must not be conflated with intrinsically invalid x64 bytes.', '',
        'Actionable static recovery work:', '',
        '- Remove next-indexed-seed walls for validated branch targets and retain overlap ownership; compare unique bytes against the same denominator.',
        '- Add validated indirect branch/case-table and tail-call targets; use CFG/vftable/relocation evidence as seeds rather than arbitrary byte offsets.',
        '- Separate unsupported instruction/processor decoding from malformed x64 encodings using a second independent decoder on the saved metadata-start samples.',
        '- Inventory readable islands and branch destinations. Preserve confidence and exact byte spans; do not count random-byte x64 resynchronization as recovered code.', '',
        f"Validated RTTI first-method seed census: {result.get('rtti_first_method_census', {})}. Candidate method pointers remain unvalidated bodies.", '',
        'The earlier linear sweep reported 102,243,840 scanned bytes and 5,514,034 invalid one-byte steps, implying 96,729,806 bytes in mechanically decodable instructions. That apparent 94.6% is not a valid reachable-code recovery result: variable-length x86 decoding often accepts random data after arbitrary resynchronization.', '',
        'Raw JSON records every sample address, original bytes, listing, source hash, section statistics and current algorithm flags. Neither this diagnostic nor absence of decoder errors establishes semantic equivalence.',
    ]
    (output/'diagnostics.md').write_text('\n'.join(lines)+'\n', encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=pathlib.Path, default=ROOT/'benchmark-inputs/RobloxPlayerBeta-0.742.exe')
    parser.add_argument('--mcp', type=pathlib.Path, default=ROOT/'dist-v0.5/ScratcherMCP.exe')
    parser.add_argument('--output', type=pathlib.Path, default=ROOT/'reports/coverage-70')
    parser.add_argument('--samples', type=int, default=128)
    args = parser.parse_args()
    start = time.perf_counter()
    pe = PE(args.input)
    assert pe.digest == EXPECTED, 'Expected immutable Roblox version; no denominator substitution'
    cfg, metadata = pe.cfg()
    candidate_sections = {pe.section(x['va'])['name'] for x in cfg if pe.section(x['va']) and not x['flags'] & 1}
    if pe.section(pe.entry):
        candidate_sections.add(pe.section(pe.entry)['name'])
    candidate_sections.update(s['name'] for s in pe.sections if s['flags'] & 0x20000000)
    result = dict(input=dict(path=str(args.input), sha256=pe.digest, size_bytes=len(pe.data)),
                  method='Static original-file byte statistics and deterministic metadata-backed start samples; no arbitrary-start sweep',
                  mcp=dict(path=str(args.mcp), sha256=hashlib.sha256(args.mcp.read_bytes()).hexdigest()),
                  cfg=metadata, sections=[])
    counts = collections.Counter(pe.section(x['va'])['name'] if pe.section(x['va']) else 'unmapped' for x in cfg)
    for s in pe.sections:
        data = pe.data[s['offset']:s['offset']+s['size']]
        windows = [entropy(data[at:at+65536]) for at in range(0, len(data), 65536)]
        frequencies = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        top = np.argsort(frequencies)[-8:][::-1]
        result['sections'].append(dict(s, va=hex(s['va']), declared_execute=bool(s['flags'] & 0x20000000),
            candidate_scope=s['name'] in candidate_sections, entropy_bits_per_byte=entropy(data),
            window_entropy=quantiles(windows), window_count=len(windows),
            window_entropy_above_7_9=sum(x > 7.9 for x in windows), cfg_starts=counts[s['name']],
            most_frequent_bytes=[dict(byte=hex(int(b)), count=int(frequencies[b])) for b in top]))
    result['raw_candidate_section_bytes_including_alignment_padding'] = sum(s['size'] for s in result['sections'] if s['candidate_scope'])
    result['candidate_scope_bytes_excluding_file_alignment_padding'] = sum(min(s['size'], s['virtual_size']) for s in result['sections'] if s['candidate_scope'])
    result['candidate_scope_bytes'] = result['raw_candidate_section_bytes_including_alignment_padding']
    result['candidate_scope_policy'] = 'Match current Binary::parsePE mapper: memorySize=max(VirtualSize,SizeOfRawData); file-backed extent=min(fileSize,memorySize). Includes raw alignment padding. Immutable input and scope.'
    result['target_70_bytes'] = (7*result['candidate_scope_bytes']+9)//10
    gaps = [b['va']-a['va'] for a,b in zip(cfg,cfg[1:]) if pe.section(a['va']) == pe.section(b['va'])]
    result['cfg_spacing'] = quantiles(gaps)
    result['samples'] = []
    with Client(args.mcp) as client:
        result['open'] = client.tool('open_binary', dict(path=str(args.input)), 60)
        result['code_paths'] = client.tool('analyze_code_paths', dict(instruction_budget=100000000,
            byte_budget=536870912, time_budget_ms=60000, coverage_span_budget=4000000), 90)
        aggregates = collections.Counter()
        known_starts = set()
        invalid_rows, boundary_rows, closed_rows = [], [], []
        offset = 0
        while True:
            page = client.tool('get_code_analysis', dict(view='functions', offset=offset, limit=5000), 60)
            for row in page['items']:
                known_starts.add(int(row['address'], 16))
                aggregates['rows'] += 1
                for name in ('invalid_stops', 'boundary_reached', 'unresolved_indirect_edges', 'edges_outside_boundary', 'overlapping_targets', 'limit_reached'):
                    aggregates[name+'_rows'] += bool(row[name])
                if row['invalid_stops']:
                    invalid_rows.append(row)
                if row['boundary_reached']:
                    boundary_rows.append(row)
                if row['traversal_closed']:
                    closed_rows.append(row)
            offset += len(page['items'])
            if offset >= page['total']:
                break
        result['traversal_population'] = dict(aggregates)
        groups = [('cfg_address_quantiles', [dict(address=hex(x['va'])) for x in evenly(cfg, args.samples)]),
                  ('invalid_traversal_quantiles', evenly(invalid_rows, 32)),
                  ('boundary_traversal_quantiles', evenly(boundary_rows, 32)),
                  ('closed_traversal_quantiles', evenly(closed_rows, 16))]
        sampled = set()
        for selection, rows in groups:
            for row in rows:
                va = int(row['address'], 16)
                if va in sampled:
                    continue
                sampled.add(va)
                listing = client.tool('disassemble', dict(address=hex(va), count=32), 30)['instructions']
                result['samples'].append(dict(selection=selection, address=hex(va),
                    bytes_hex=pe.bytes(va, 128).hex(), entropy_128_bytes=entropy(pe.bytes(va, 128)),
                    traversal=row if 'invalid_stops' in row else None, listing=listing))
                if row.get('invalid_stops') and row.get('observed_reachable_end'):
                    at = int(row['observed_reachable_end'], 16)
                    result['samples'][-1]['observed_end_probe'] = dict(address=hex(at), bytes_hex=pe.bytes(at, 32).hex(),
                        interpretation='Maximum observed end may not be the failing path when branches exist',
                        listing=client.tool('disassemble', dict(address=hex(at), count=3), 30)['instructions'])
        # Independent controls measure accidental decoder acceptance. They are not seeds.
        text = next(s for s in pe.sections if s['name'] == '.text')
        rng = np.random.default_rng(742)
        result['random_offset_controls'] = []
        for delta in rng.integers(0, text['size']-256, size=128):
            va = text['va']+int(delta)
            listing = client.tool('disassemble', dict(address=hex(va), count=32), 30)['instructions']
            result['random_offset_controls'].append(dict(address=hex(va), bytes_hex=pe.bytes(va, 128).hex(),
                selection='Seed742 diagnostic control only; never submitted as a function or coverage seed', listing=listing))
        result['rtti_summary'] = client.tool('analyze_rtti', {}, 60)
        methods, tables = set(), 0
        offset = 0
        while True:
            page = client.tool('get_rtti', dict(offset=offset, limit=500, max_output_bytes=8388608), 60)
            for row in page['items']:
                for table in row['vftables']:
                    methods.add(int(table['first_method'], 16))
                    tables += 1
            offset = page['next_offset']
            if offset >= page['total']:
                break
            assert page['items'], 'RTTI page unexpectedly empty'
        missing = sorted(methods-known_starts)
        missing_samples = []
        for va in evenly(missing, 64):
            missing_samples.append(dict(address=hex(va), bytes_hex=pe.bytes(va, 128).hex(),
                listing=client.tool('disassemble', dict(address=hex(va), count=32), 30)['instructions']))
        result['rtti_missing_first_method_samples'] = missing_samples
        result['rtti_first_method_census'] = dict(validated_vftables=tables, unique_first_methods=len(methods),
            missing_from_all_current_function_starts=len(missing), missing_first_methods=[hex(x) for x in missing],
            sampled_missing_methods=len(missing_samples),
            sampled_missing_first_decode_invalid=sum(bool(s['listing']) and s['listing'][0]['mnemonic']=='db' for s in missing_samples))
        result['mcp_memory'] = client.memory()
    result['sample_summary'] = dict(count=len(result['samples']),
        first_instruction_invalid=sum(bool(s['listing']) and s['listing'][0]['mnemonic'] == 'db' for s in result['samples']),
        invalid_within_32_instruction_listing=sum(any(i['mnemonic'] == 'db' for i in s['listing']) for s in result['samples']))
    def sample_stats(rows):
        return dict(count=len(rows),
            first_instruction_invalid=sum(bool(s['listing']) and s['listing'][0]['mnemonic']=='db' for s in rows),
            invalid_within_32_instruction_listing=sum(any(i['mnemonic']=='db' for i in s['listing']) for s in rows))
    result['sample_summary']['cfg_quantiles'] = sample_stats([s for s in result['samples'] if s['selection']=='cfg_address_quantiles'])
    result['sample_summary']['random_offset_controls'] = sample_stats(result['random_offset_controls'])
    probes = [s['observed_end_probe'] for s in result['samples'] if 'observed_end_probe' in s]
    result['sample_summary']['observed_end_probes'] = dict(sample_stats(probes),
        first_byte_histogram=dict(collections.Counter(p['bytes_hex'][:2] for p in probes)),
        potentially_cut_off_valid_instructions=sum(bool(s['observed_end_probe']['listing']) and
            s['observed_end_probe']['listing'][0]['mnemonic']!='db' and
            int(s['observed_end_probe']['address'], 16)+s['observed_end_probe']['listing'][0]['length']>
            int(s['traversal']['traversal_boundary'], 16) for s in result['samples'] if 'observed_end_probe' in s))
    fixture = ROOT/'build/Release/ScratcherAnalysisFixture.exe'
    if fixture.exists():
        comparison = PE(fixture)
        result['readable_fixture_control'] = dict(path=str(fixture), sha256=comparison.digest,
            executable_sections=[dict(name=s['name'], bytes=s['size'], entropy_bits_per_byte=entropy(comparison.data[s['offset']:s['offset']+s['size']]))
                for s in comparison.sections if s['flags'] & 0x20000000])
    assert hashlib.sha256(args.input.read_bytes()).hexdigest() == pe.digest
    result['elapsed_seconds'] = time.perf_counter()-start
    write_report(result, args.output)
    print(json.dumps({k:result[k] for k in ('candidate_scope_bytes', 'target_70_bytes', 'sample_summary', 'elapsed_seconds')}))
    print(args.output/'diagnostics.md')


if __name__ == '__main__':
    main()
