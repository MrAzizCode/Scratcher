"""Read-only qualification of a preexisting raw code image against captured code."""
import hashlib
import importlib
import json
import pathlib
import time

import numpy as np

h=importlib.import_module('inspect-roblox-dumps')
p=importlib.import_module('probe-code-transform')
ROOT=pathlib.Path('D:/Scratcher')
SOURCE=ROOT / 'benchmark-inputs/roblox_text_dump.bin'


def pe_metadata(path):
    pe=h.PE(path)
    at,=pe.read('<I',0x3c)
    optional=at+24
    return dict(path=str(path),sha256=pe.digest,file_bytes=len(pe.data),timestamp=pe.read('<I',at+8)[0],
        image_size=pe.read('<I',optional+56)[0],checksum=pe.read('<I',optional+64)[0],
        text_sections=[dict(rva=hex(s['va']-pe.base),virtual_size=s['virtual_size'],raw_size=s['size']) for s in pe.sections if s['name']=='.text'])


def main():
    start=time.perf_counter()
    data=SOURCE.read_bytes()
    original=h.PE(ROOT/'benchmark-inputs/RobloxPlayerBeta-0.742.exe')
    assert original.digest==h.EXPECTED
    text=next(s for s in original.sections if s['name']=='.text')
    raw_rva=0x1000
    result=dict(source=dict(path=str(SOURCE),file_bytes=len(data),sha256=hashlib.sha256(data).hexdigest()),
        original=pe_metadata(ROOT/'benchmark-inputs/RobloxPlayerBeta-0.742.exe'),assumed_raw_start_rva=hex(raw_rva),
        method='Static existing file only; exact same-RVA code comparisons against physically captured metadata-qualified current-build minidump .text. No process reads, target execution, capture, foreign script execution or merged snapshots.',
        source_has_read_success_bitmap=False,source_embeds_build_identity=False,
        provenance_limit='Foreign read_all_text.py reportedly prezero-allocates 1MiB read buffers without a failure mask; file existence, byte count, readable opcodes and zeros do not prove full successful capture.',
        snapshot_comparisons=[])
    old=ROOT / 'benchmark-inputs/RobloxPlayerBeta.exe.sample'
    if old.exists():
        result['foreign_original_sample']=pe_metadata(old)
    reloc=p.relocation_ranges(original)
    inventory=json.loads((ROOT/'reports/coverage-70/dump-inventory.json').read_text())
    for row in inventory['dumps']:
        qualified=[m for m in row.get('module_results',[]) if m.get('identity_metadata_qualified')]
        if not qualified:
            continue
        dump=h.Dump(pathlib.Path(row['path']))
        try:
            compared=matched=excluded_compared=excluded_matched=0
            mismatches_raw_zero=0
            samples=[]
            for module in qualified:
                for piece in module['candidate_pieces_for_code_only_replay']:
                    low,high=int(piece['start_rva'],16),int(piece['end_rva'],16)
                    lo,hi=max(low,raw_rva),min(high,raw_rva+len(data))
                    if lo>=hi:
                        continue
                    snapshot_at=piece['dump_file_offset']+lo-low
                    raw=np.frombuffer(data[lo-raw_rva:hi-raw_rva],dtype=np.uint8)
                    captured=np.frombuffer(dump.data[snapshot_at:snapshot_at+hi-lo],dtype=np.uint8)
                    matches=raw==captured
                    compared+=len(raw)
                    matched+=int(np.count_nonzero(matches))
                    mismatches_raw_zero+=int(np.count_nonzero((~matches)&(raw==0)))
                    mask=np.ones(len(raw),dtype=bool)
                    for a,b in reloc:
                        if a<hi and b>lo:
                            mask[max(0,a-lo):min(len(raw),b-lo)]=False
                    excluded_compared+=int(np.count_nonzero(mask))
                    excluded_matched+=int(np.count_nonzero(matches&mask))
                for sample in module['cfg_start_samples']:
                    rva=int(sample['rva'],16)
                    if raw_rva<=rva and rva+16<=raw_rva+len(data):
                        candidate=data[rva-raw_rva:rva-raw_rva+16].hex()
                        samples.append(dict(rva=sample['rva'],raw_image_hex=candidate,
                            captured_code_hex=sample['captured_code_hex'],original_code_hex=sample['original_code_hex'],
                            raw_matches_captured=candidate==sample['captured_code_hex']))
            result['snapshot_comparisons'].append(dict(dump_path=row['path'],dump_sha256=row['dump_sha256'],
                compared_code_bytes=compared,exact_matches=matched,different_bytes=compared-matched,
                exact_match_percent=100*matched/compared if compared else None,
                mismatches_with_zero_raw_image_byte=mismatches_raw_zero,
                relocation_excluded_observations=excluded_compared,relocation_excluded_exact_matches=excluded_matched,
                relocation_excluded_exact_percent=100*excluded_matched/excluded_compared if excluded_compared else None,
                metadata_anchor_samples=samples))
        finally:
            dump.close()
    print(json.dumps(dict(source=result['source'],snapshot_results=[{k:x[k] for k in ('dump_path','compared_code_bytes','exact_match_percent','relocation_excluded_exact_percent')} for x in result['snapshot_comparisons']])),flush=True)
    values=np.frombuffer(data,dtype=np.uint8)
    chunks=[]
    for at in range(0,len(data),1<<20):
        chunk=data[at:at+(1<<20)]
        source_chunk=original.data[text['offset']+at:text['offset']+at+len(chunk)]
        tail_zero=len(chunk)-len(chunk.rstrip(b'\x00'))
        chunks.append(dict(file_offset=at,start_rva=hex(raw_rva+at),bytes=len(chunk),all_zero=not any(chunk),
            zero_byte_count=chunk.count(0),trailing_zero_bytes=tail_zero,
            conservative_nonzero_prefix_bytes=len(chunk)-tail_zero,
            entropy_bits_per_byte=h.entropy(chunk),
            byte_differences_from_original=int(np.count_nonzero(np.frombuffer(chunk,dtype=np.uint8)!=np.frombuffer(source_chunk,dtype=np.uint8))),
            original_image_byte_agreement_percent=100*int(np.count_nonzero(np.frombuffer(chunk,dtype=np.uint8)==np.frombuffer(source_chunk,dtype=np.uint8)))/len(chunk)))
    zero=values==0
    # Boolean boundaries encode long zero runs without exposing raw code beyond anchors.
    changes=np.flatnonzero(np.diff(np.r_[False,zero,False].astype(np.int8)))
    zero_runs=[(int(a),int(b)) for a,b in zip(changes[::2],changes[1::2]) if b-a>=4096]
    result.update(full_entropy_bits_per_byte=h.entropy(data),zero_byte_count=int(np.count_nonzero(zero)),
        one_mib_chunks=chunks,all_zero_chunk_bytes=sum(x['bytes'] for x in chunks if x['all_zero']),
        zero_runs_at_least_4096=[dict(file_offset=a,start_rva=hex(raw_rva+a),bytes=b-a) for a,b in zero_runs],
        bytes_in_long_zero_runs=sum(b-a for a,b in zero_runs),largest_zero_run_bytes=max((b-a for a,b in zero_runs),default=0),
        physically_present_file_bytes=len(data),read_success_verified_bytes=0,
        one_mib_trailing_zero_bytes=sum(x['trailing_zero_bytes'] for x in chunks),
        conservative_nonzero_prefix_candidate_bytes=sum(x['conservative_nonzero_prefix_bytes'] for x in chunks),
        original_file_exact_agreement_bytes=sum(x['bytes']-x['byte_differences_from_original'] for x in chunks),
        original_text_virtual_size_matches=len(data)==text['virtual_size'],
        original_text_raw_size_matches=len(data)==text['size'],
        inferred_identity='Conditional only: size and exact overlap can support current-build association, but raw image lacks embedded module identity/read-success evidence.',
        seventy_percent_goal_verified=False,whole_image_provenance_verified=False,elapsed_seconds=time.perf_counter()-start)
    out=ROOT/'reports/coverage-70'
    (out/'existing-code-image.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    lines=['# Existing raw code image qualification','',
        f"Source `{SOURCE}`: **{len(data):,} bytes**, SHA256 `{result['source']['sha256']}`. Assumed start RVA `0x1000` is tested against existing current-build snapshot code. No foreign scripts or target processes were run.",'',
        '| Snapshot | Exact overlap observations | Exact agreement | Relocation-excluded agreement |',
        '|---|---:|---:|---:|']
    for row in result['snapshot_comparisons']:
        lines.append(f"| {pathlib.Path(row['dump_path']).name} | {row['compared_code_bytes']:,} | {row['exact_match_percent']:.6f}% | {row['relocation_excluded_exact_percent']:.6f}% |")
    lines += ['',f"Image size {'matches' if result['original_text_virtual_size_matches'] else 'does not match'} original 0.742 `.text` VirtualSize ({text['virtual_size']:,}); raw section bytes include alignment padding ({text['size']:,}). Size agreement alone is not build proof.",'',
        f"Full entropy: **{result['full_entropy_bits_per_byte']:.6f} bits/byte**. All-zero 1MiB chunks total **{result['all_zero_chunk_bytes']:,} bytes**. Long zero runs (at least 4096 bytes) total **{result['bytes_in_long_zero_runs']:,} bytes**; largest **{result['largest_zero_run_bytes']:,} bytes**. These may be holes, padding or legitimate zero data; no successful-read claim follows from them.",'',
        f"A conservative exclusion of every 1MiB chunk's trailing zero suffix removes **{result['one_mib_trailing_zero_bytes']:,} bytes**, leaving **{result['conservative_nonzero_prefix_candidate_bytes']:,} candidate bytes**; that count is not verified successful capture. Exact byte agreement with original on-disk `.text`: **{result['original_file_exact_agreement_bytes']:,} bytes**. Per-chunk entropy and agreement remain in JSON, separating mixed original-like and changed bytes descriptively.",'',
        'The image contains physically present bytes, but no read-success bitmap or embedded module identity. The preexisting capture script used prezeroallocated buffers and did not retain failures. Missing reads may therefore appear as zeros. Snapshot matches validate only their exact observed RVA overlap, not every other raw-image byte.','',
        '**70% completion remains unverified.** The artifact is a concrete conditional readable-code candidate for a provenance-aware decode experiment. Keep the original candidate denominator unchanged, exclude unknown zero-filled holes, and report original-file versus snapshot-source coverage separately. Do not silently replace the original input or combine conflicting runtimes.']
    (out/'existing-code-image.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('full_entropy_bits_per_byte','all_zero_chunk_bytes','bytes_in_long_zero_runs','largest_zero_run_bytes','elapsed_seconds')}))


if __name__=='__main__':
    main()
