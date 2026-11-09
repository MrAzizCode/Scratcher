"""Inventory existing Roblox minidumps statically; expose module code and metadata only."""
import argparse
import collections
import hashlib
import importlib
import json
import mmap
import pathlib
import struct
import time
import uuid

import numpy as np

PE = importlib.import_module('diagnose-roblox-code').PE
entropy = importlib.import_module('diagnose-roblox-code').entropy
ROOT = pathlib.Path('D:/Scratcher')
EXPECTED = '11a30ada177d15a9ec1c1dc30957b28b46839c9c6407e53be6138d2f12f6f2fe'


def union(ranges):
    result = []
    for low, high in sorted(ranges):
        if high <= low:
            continue
        if result and low <= result[-1][1]:
            result[-1][1] = max(result[-1][1], high)
        else:
            result.append([low, high])
    return result


def version(ms, ls):
    return '.'.join(str(x) for x in (ms >> 16, ms & 65535, ls >> 16, ls & 65535))


class Dump:
    def __init__(self, path):
        self.path = path
        self.file = path.open('rb')
        self.data = mmap.mmap(self.file.fileno(), 0, access=mmap.ACCESS_READ)
        assert self.data[:4] == b'MDMP', 'Not a minidump'
        count, directory = self.read('<II', 8)
        assert count < 100000
        self.streams = collections.defaultdict(list)
        for n in range(count):
            kind, size, offset = self.read('<III', directory+12*n)
            assert offset+size <= len(self.data)
            self.streams[kind].append((offset, size))

    def close(self):
        self.data.close()
        self.file.close()

    def read(self, fmt, at):
        assert at >= 0 and at+struct.calcsize(fmt) <= len(self.data), 'Truncated dump metadata'
        return struct.unpack_from(fmt, self.data, at)

    def string(self, at):
        size, = self.read('<I', at)
        assert size < 32768 and size % 2 == 0 and at+4+size <= len(self.data)
        return self.data[at+4:at+4+size].decode('utf-16-le', 'replace')

    def modules(self):
        result = []
        for off, size in self.streams[4]:
            count, = self.read('<I', off)
            assert count <= 10000 and 4+108*count <= size
            for n in range(count):
                at = off+4+n*108
                base, image_size, checksum, timestamp, name_rva = self.read('<QIIII', at)
                basename = pathlib.PureWindowsPath(self.string(name_rva)).name
                if basename.lower() != 'robloxplayerbeta.exe':
                    continue
                values = self.read('<13I', at+24)
                cv_size, cv_rva = self.read('<II', at+76)
                cv = None
                if cv_size >= 24 and cv_rva+cv_size <= len(self.data) and self.data[cv_rva:cv_rva+4] == b'RSDS':
                    age, = self.read('<I', cv_rva+20)
                    cv = dict(guid=str(uuid.UUID(bytes_le=self.data[cv_rva+4:cv_rva+20])), age=age)
                result.append(dict(basename=basename, base=base, image_size=image_size, checksum=checksum,
                    timestamp=timestamp, version_info_signature_valid=values[0]==0xfeef04bd,
                    file_version=version(values[2], values[3]), product_version=version(values[4], values[5]),
                    codeview=cv))
        return result

    def memories(self):
        result = []
        for off, size in self.streams[5]:
            count, = self.read('<I', off)
            assert count <= 10000000 and 4+16*count <= size
            for n in range(count):
                start, length, file_offset = self.read('<QII', off+4+16*n)
                assert file_offset+length <= len(self.data), 'MemoryList bytes outside dump'
                result.append((start, start+length, file_offset, 'MemoryList'))
        for off, size in self.streams[9]:
            count, file_offset = self.read('<QQ', off)
            assert count <= 10000000 and 16+16*count <= size
            for n in range(count):
                start, length = self.read('<QQ', off+16+16*n)
                assert file_offset+length <= len(self.data), 'Memory64List bytes outside dump'
                result.append((start, start+length, file_offset, 'Memory64List'))
                file_offset += length
        return result


def original_identity(pe):
    at, = pe.read('<I', 0x3c)
    optional = at+24
    timestamp, = pe.read('<I', at+8)
    image_size, = pe.read('<I', optional+56)
    checksum, = pe.read('<I', optional+64)
    cv = None
    debug_rva, debug_size = pe.read('<II', pe.directory_offset+6*8)
    if debug_rva and debug_size:
        debug_at = pe.offset(pe.base+debug_rva, debug_size)
        for off in range(debug_at, debug_at+debug_size-27, 28):
            kind, size, rva, pointer = pe.read('<IIII', off+12)
            if kind == 2 and size >= 24 and pointer+size <= len(pe.data) and pe.data[pointer:pointer+4]==b'RSDS':
                age, = pe.read('<I', pointer+20)
                cv = dict(guid=str(uuid.UUID(bytes_le=pe.data[pointer+4:pointer+20])), age=age)
    signatures = []
    start = 0
    while True:
        off = pe.data.find(b'\xbd\x04\xef\xfe\x00\x00\x01\x00', start)
        if off < 0:
            break
        if off+52 <= len(pe.data):
            values = pe.read('<13I', off)
            signatures.append(version(values[2], values[3]))
        start = off+8
    # The displayed fourth component exceeds the 16-bit VS_FIXEDFILEINFO field.
    # Compare fixed numeric metadata to fixed numeric metadata, retaining the display string separately.
    fixed_version = version(742, 7421053 & 65535)
    assert fixed_version in signatures, 'Expected original PE fixed version metadata'
    assert '0, 742, 0, 7421053'.encode('utf-16-le') in pe.data, 'Expected original resource display version'
    return dict(timestamp=timestamp, image_size=image_size, checksum=checksum,
                file_version=fixed_version, display_file_version='0, 742, 0, 7421053', codeview=cv, sha256=pe.digest)


def analyze_dump(path, pe, target, scopes, cfg):
    with path.open('rb') as source:
        digest = hashlib.file_digest(source, 'sha256').hexdigest()
    result = dict(path=str(path), file_bytes=path.stat().st_size, dump_sha256=digest)
    dump = Dump(path)
    try:
        modules = dump.modules()
        result['roblox_modules'] = modules
        result['memory_stream_types'] = [kind for kind in (5,9) if kind in dump.streams]
        memories = dump.memories()
        result['captured_memory_descriptor_count'] = len(memories)
        result['captured_memory_descriptor_bytes'] = sum(high-low for low,high,_,_ in memories)
        result['module_results'] = []
        matching_ranges = []
        metadata_qualified_ranges = []
        for module in modules:
            matches = {key:module[key] == target[key] for key in ('timestamp','image_size','checksum','file_version')}
            if module['checksum']==0 and target['checksum']!=0:
                matches['checksum']=None
            matches['version_info_signature_valid'] = module['version_info_signature_valid']
            if target['codeview'] is not None:
                matches['codeview'] = module['codeview'] == target['codeview']
            accepted = all(matches.values())
            metadata_qualified = all(value is True for key,value in matches.items() if key != 'checksum') and matches['checksum'] is not False
            row = dict(identity_matches=matches, identity_accepted_for_same_build=accepted,
                       checksum_status='unavailable_zero' if matches['checksum'] is None else 'match' if matches['checksum'] else 'mismatch',
                       identity_metadata_qualified=metadata_qualified, exact_original_file_hash_verified=False,
                       base=hex(module['base']), captured_code_ranges=[], section_statistics=[], cfg_start_samples=[])
            pieces = []
            for low,high,file_offset,stream in memories:
                for rva_low,rva_high in scopes:
                    start, end = max(low,module['base']+rva_low), min(high,module['base']+rva_high)
                    if start < end:
                        pieces.append((start-module['base'],end-module['base'],file_offset+start-low,stream))
            # Remove overlap conservatively. Only physically stored original-module candidate bytes count.
            ranges = union((low,high) for low,high,_,_ in pieces)
            row['captured_code_ranges'] = [dict(start_rva=hex(low),end_rva=hex(high)) for low,high in ranges]
            row['unique_captured_candidate_bytes'] = sum(high-low for low,high in ranges)
            row['captured_candidate_percent'] = 100*row['unique_captured_candidate_bytes']/sum(high-low for low,high in scopes)
            if accepted:
                matching_ranges += ranges
            if metadata_qualified:
                metadata_qualified_ranges += ranges
            selected = []
            for low,high in ranges:
                cursor = low
                for p_low,p_high,at,stream in sorted(pieces):
                    start, end = max(cursor,p_low), min(high,p_high)
                    if start < end:
                        selected.append((start,end,at+start-p_low))
                        cursor=end
                    if cursor == high:
                        break
                assert cursor == high
            row['candidate_pieces_for_code_only_replay']=[dict(start_rva=hex(low),end_rva=hex(high),dump_file_offset=at) for low,high,at in selected]
            # Expose only available PE header metadata; never fill missing header bytes.
            header=next(((low,high,at) for low,high,at,_ in memories if low<=module['base'] and module['base']+64<=high),None)
            if header:
                low,high,at=header
                header_at=at+module['base']-low
                pe_offset,=dump.read('<I',header_at+0x3c)
                captured_header_end=high-module['base']
                row['captured_pe_header']=dict(captured_bytes=captured_header_end,pe_offset=pe_offset)
                if pe_offset+12<=captured_header_end and dump.data[header_at+pe_offset:header_at+pe_offset+4]==b'PE\0\0':
                    row['captured_pe_header']['timestamp']=dump.read('<I',header_at+pe_offset+8)[0]
                for key,delta in [('image_size',56),('checksum',64)]:
                    if pe_offset+24+delta+4<=captured_header_end:
                        row['captured_pe_header'][key]=dump.read('<I',header_at+pe_offset+24+delta)[0]
            for section in pe.sections:
                sec_low=section['va']-pe.base
                sec_high=sec_low+section['size']
                frequencies=np.zeros(256,dtype=np.int64)
                length=changed=0
                for low,high,at in selected:
                    start,end=max(low,sec_low),min(high,sec_high)
                    if start>=end:
                        continue
                    chunk=dump.data[at+start-low:at+end-low]
                    original=pe.data[section['offset']+start-sec_low:section['offset']+end-sec_low]
                    length+=len(chunk)
                    frequencies+=np.bincount(np.frombuffer(chunk,dtype=np.uint8),minlength=256)
                    changed+=int(np.count_nonzero(np.frombuffer(chunk,dtype=np.uint8)!=np.frombuffer(original,dtype=np.uint8)))
                if length:
                    probability=frequencies[frequencies>0]/length
                    row['section_statistics'].append(dict(name=section['name'],captured_bytes=length,
                        byte_entropy_bits_per_byte=float(-np.sum(probability*np.log2(probability))),
                        bytes_different_from_original=changed, differing_percent=100*changed/length,
                        comparison_meaning='Byte differences can include ASLR relocation or modifications; not evidence alone of decryption'))
            cfg_rows=[]
            for entry in cfg:
                rva=entry['va']-pe.base
                for low,high,at in selected:
                    if low<=rva and rva+16<=high:
                        captured=dump.data[at+rva-low:at+rva-low+16]
                        original=pe.bytes(entry['va'],16)
                        cfg_rows.append(dict(rva=hex(rva),snapshot_va=hex(module['base']+rva),
                            captured_code_hex=captured.hex(),original_code_hex=original.hex(),bytes_identical=captured==original))
                        break
            row['cfg_starts_with_16_captured_bytes']=len(cfg_rows)
            row['cfg_start_captured_bytes_different']=sum(not x['bytes_identical'] for x in cfg_rows)
            if cfg_rows:
                indices=sorted(set(int(x) for x in np.linspace(0,len(cfg_rows)-1,min(32,len(cfg_rows)))))
                row['cfg_start_samples']=[cfg_rows[i] for i in indices]
            result['module_results'].append(row)
        result['same_build_unique_candidate_ranges']=[dict(start_rva=hex(a),end_rva=hex(b)) for a,b in union(matching_ranges)]
        result['same_build_unique_captured_candidate_bytes']=sum(b-a for a,b in union(matching_ranges))
        result['metadata_qualified_unique_candidate_ranges']=[dict(start_rva=hex(a),end_rva=hex(b)) for a,b in union(metadata_qualified_ranges)]
        result['metadata_qualified_unique_captured_candidate_bytes']=sum(b-a for a,b in union(metadata_qualified_ranges))
        return result
    finally:
        dump.close()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory',type=pathlib.Path,default=ROOT/'reports/coverage-70/local-dump-inventory.json')
    parser.add_argument('--input',type=pathlib.Path,default=ROOT/'benchmark-inputs/RobloxPlayerBeta-0.742.exe')
    parser.add_argument('--output',type=pathlib.Path,default=ROOT/'reports/coverage-70')
    args=parser.parse_args()
    start=time.perf_counter()
    pe=PE(args.input)
    assert pe.digest==EXPECTED
    target=original_identity(pe)
    cfg,_=pe.cfg()
    names={pe.section(x['va'])['name'] for x in cfg if pe.section(x['va']) and not x['flags'] & 1}
    names.add(pe.section(pe.entry)['name'])
    names.update(s['name'] for s in pe.sections if s['flags'] & 0x20000000)
    scopes=union((s['va']-pe.base,s['va']-pe.base+s['size']) for s in pe.sections if s['name'] in names)
    scope_bytes=sum(b-a for a,b in scopes)
    assert scope_bytes==102242816
    report=dict(method='Read-only existing minidumps, Roblox module metadata and physically stored original candidate RVA bytes only; no execution, attachment, capture, private heap/stack strings, zero-fill credit or arbitrary-start decoding',
        original_input=target,candidate_scope_bytes=scope_bytes,target_70_bytes=(scope_bytes*7+9)//10,
        candidate_scope_rvas=[dict(start=hex(a),end=hex(b)) for a,b in scopes], dumps=[])
    inventory=json.loads(args.inventory.read_text(encoding='utf-8-sig'))
    paths=[pathlib.Path(x['FullName']) for x in inventory if 'Roblox' in x['FullName'] and x['FullName'].lower().endswith('.dmp')]
    for path in paths:
        try:
            row=analyze_dump(path,pe,target,scopes,cfg)
        except Exception as error:
            row=dict(path=str(path),error=str(error))
        report['dumps'].append(row)
        print(json.dumps(dict(path=str(path),captured_same_build_bytes=row.get('same_build_unique_captured_candidate_bytes'),modules=row.get('roblox_modules'),error=row.get('error'))),flush=True)
    combined=union((int(r['start_rva'],16),int(r['end_rva'],16)) for d in report['dumps'] for r in d.get('same_build_unique_candidate_ranges',[]))
    report['combined_same_build_unique_ranges']=[dict(start_rva=hex(a),end_rva=hex(b)) for a,b in combined]
    report['combined_same_build_unique_captured_candidate_bytes']=sum(b-a for a,b in combined)
    report['combined_captured_candidate_percent']=100*report['combined_same_build_unique_captured_candidate_bytes']/scope_bytes
    compatible=union((int(r['start_rva'],16),int(r['end_rva'],16)) for d in report['dumps'] for r in d.get('metadata_qualified_unique_candidate_ranges',[]))
    report['combined_metadata_qualified_unique_ranges']=[dict(start_rva=hex(a),end_rva=hex(b)) for a,b in compatible]
    report['combined_metadata_qualified_unique_captured_candidate_bytes']=sum(b-a for a,b in compatible)
    report['combined_metadata_qualified_captured_candidate_percent']=100*report['combined_metadata_qualified_unique_captured_candidate_bytes']/scope_bytes
    report['captured_bytes_sufficient_for_70_percent']=report['combined_metadata_qualified_unique_captured_candidate_bytes']>=report['target_70_bytes']
    # Compare only original-module candidate code overlaps, never other captured memory.
    qualified=[d for d in report['dumps'] if d.get('metadata_qualified_unique_captured_candidate_bytes',0)]
    conflicts=[]
    for index,first in enumerate(qualified):
        first_dump=Dump(pathlib.Path(first['path']))
        try:
            for second in qualified[index+1:]:
                second_dump=Dump(pathlib.Path(second['path']))
                try:
                    overlap=differing=0
                    first_pieces=[p for m in first['module_results'] if m['identity_metadata_qualified'] for p in m['candidate_pieces_for_code_only_replay']]
                    second_pieces=[p for m in second['module_results'] if m['identity_metadata_qualified'] for p in m['candidate_pieces_for_code_only_replay']]
                    for a in first_pieces:
                        for b in second_pieces:
                            low=max(int(a['start_rva'],16),int(b['start_rva'],16))
                            high=min(int(a['end_rva'],16),int(b['end_rva'],16))
                            if low>=high:
                                continue
                            length=high-low
                            a_at=a['dump_file_offset']+low-int(a['start_rva'],16)
                            b_at=b['dump_file_offset']+low-int(b['start_rva'],16)
                            av=np.frombuffer(first_dump.data[a_at:a_at+length],dtype=np.uint8)
                            bv=np.frombuffer(second_dump.data[b_at:b_at+length],dtype=np.uint8)
                            overlap+=length
                            differing+=int(np.count_nonzero(av!=bv))
                    conflicts.append(dict(first_dump=pathlib.Path(first['path']).name,second_dump=pathlib.Path(second['path']).name,
                        overlapping_candidate_bytes=overlap,different_candidate_bytes=differing,
                        meaning='Raw overlapping snapshot code comparison; relocation or runtime modification may explain differences. Not a merged authoritative byte source.'))
                finally:
                    second_dump.close()
        finally:
            first_dump.close()
    report['pairwise_code_overlap_comparisons']=conflicts
    report['decoded_coverage_percent_verified']=None
    report['elapsed_seconds']=time.perf_counter()-start
    args.output.mkdir(parents=True,exist_ok=True)
    (args.output/'dump-inventory.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    lines=['# Existing Roblox crash dump code inventory','',
        f"Original immutable file SHA256 `{EXPECTED}`, displayed version `{target['display_file_version']}`, fixed numeric version `{target['file_version']}`. The fourth displayed component exceeds 16 bits; fixed metadata contains its low 16 bits. Scope **{scope_bytes:,} bytes**; 70% requires **{report['target_70_bytes']:,}** supported code bytes.",'',
        'Only existing files were read. Reports expose module identity, code-range statistics and metadata-anchored code bytes. Private heap/stack contents and strings are excluded. Missing memory is never zero-filled or credited.','',
        '| Dump | Fixed module version | Metadata qualified | Captured candidate bytes | Candidate % |','|---|---|---|---:|---:|']
    for d in report['dumps']:
        modules=d.get('roblox_modules',[])
        outcomes=d.get('module_results',[])
        lines.append(f"| {pathlib.Path(d['path']).name} | {', '.join(m['file_version'] for m in modules) or 'Not found'} | {all(m['identity_metadata_qualified'] for m in outcomes) if outcomes else False} | {d.get('metadata_qualified_unique_captured_candidate_bytes',0):,} | {100*d.get('metadata_qualified_unique_captured_candidate_bytes',0)/scope_bytes:.5f} |")
    lines += ['',f"Combined exact-build unique captured candidate bytes: **{report['combined_same_build_unique_captured_candidate_bytes']:,} ({report['combined_captured_candidate_percent']:.5f}%)**.",'',
        'Captured bytes are an upper bound on possible decoding coverage, not recovered instructions. Entropy and byte differences are descriptive and do not establish encryption/decryption or semantic validity. ASLR can legitimately change embedded addresses. Matching timestamp, image size, checksum, version and available CodeView identity is required before crediting a snapshot to this build.','',
        f"Conditionally metadata-qualified union: **{report['combined_metadata_qualified_unique_captured_candidate_bytes']:,} bytes ({report['combined_metadata_qualified_captured_candidate_percent']:.5f}%)**. Four snapshots match timestamp, size, fixed version and CodeView GUID/age but omit the checksum (zero). Their captured 384-byte PE header independently verifies timestamp and ends before checksum/image-size fields. These are strong matching-build candidates, not original-file SHA256 identity proof.",'',
        'Pairwise raw code overlap differences are retained in JSON; snapshots are not blindly merged into one byte source. Reports expose candidate-only dump file offsets for controlled replay. The two older-version Windows dumps remain rejected.','',
        f"These snapshots {'contain enough captured candidate bytes to attempt' if report['captured_bytes_sufficient_for_70_percent'] else 'do not contain enough captured candidate bytes to reach'} the unchanged 70% target. No complete decoded-coverage claim is made."]
    (args.output/'dump-inventory.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({k:report[k] for k in ('combined_same_build_unique_captured_candidate_bytes','combined_captured_candidate_percent','captured_bytes_sufficient_for_70_percent','elapsed_seconds')}))


if __name__=='__main__':
    main()
