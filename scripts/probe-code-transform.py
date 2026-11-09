"""Bounded static known-code probes; never modifies or executes a target."""
import hashlib
import importlib
import json
import pathlib
import time

import numpy as np

helpers = importlib.import_module('inspect-roblox-dumps')
ROOT = pathlib.Path('D:/Scratcher')


def relocation_ranges(pe):
    rva, size = pe.read('<II', pe.directory_offset+5*8)
    result = []
    if not rva or not size:
        return result
    offset = pe.offset(pe.base+rva, size)
    end = offset+size
    while offset+8 <= end:
        page, block_size = pe.read('<II', offset)
        if block_size < 8 or offset+block_size > end:
            break
        for at in range(offset+8, offset+block_size-1, 2):
            item, = pe.read('<H', at)
            kind, delta = item >> 12, item & 4095
            if kind in (3,10):
                result.append((page+delta,page+delta+(8 if kind==10 else 4)))
        offset += block_size
    return result


def code_pairs(row, pe, excluded):
    module = next(x for x in row['module_results'] if x['identity_metadata_qualified'])
    addresses, original, snapshot = [], [], []
    dump = helpers.Dump(pathlib.Path(row['path']))
    try:
        for piece in module['candidate_pieces_for_code_only_replay']:
            low,high = int(piece['start_rva'],16),int(piece['end_rva'],16)
            section = pe.section(pe.base+low)
            if not section or section['name'] != '.text':
                continue
            rvas = np.arange(low,high,dtype=np.uint64)
            mask = np.ones(len(rvas),dtype=bool)
            for a,b in excluded:
                if a<high and b>low:
                    mask &= (rvas<a)|(rvas>=b)
            if not np.any(mask):
                continue
            file_at = pe.offset(pe.base+low,high-low)
            dump_at = piece['dump_file_offset']
            addresses.append(rvas[mask])
            original.append(np.frombuffer(pe.data[file_at:file_at+high-low],dtype=np.uint8)[mask])
            snapshot.append(np.frombuffer(dump.data[dump_at:dump_at+high-low],dtype=np.uint8)[mask])
    finally:
        dump.close()
    return tuple(np.concatenate(x) if x else np.array([],dtype=np.uint64 if i==0 else np.uint8)
                 for i,x in enumerate((addresses,original,snapshot)))


def score(prediction, actual, eligible=None):
    if eligible is None:
        eligible=np.ones(len(actual),dtype=bool)
    n=int(np.count_nonzero(eligible))
    matched=int(np.count_nonzero((prediction==actual)&eligible))
    return dict(observations=n, exact_byte_matches=matched, exact_match_percent=100*matched/n if n else None)


def periodic_probe(train, heldout, period, coordinates, random_actual):
    tva,tx,ty=train
    hva,hx,hy=heldout
    ts=(coordinates(tva)%period).astype(np.int64)
    hs=(coordinates(hva)%period).astype(np.int64)
    delta=tx^ty
    counts=np.bincount(ts*256+delta,minlength=period*256).reshape(period,256)
    key=np.argmax(counts,axis=1).astype(np.uint8)
    observations=np.sum(counts,axis=1)
    distinct=np.count_nonzero(counts,axis=1)
    eligible=observations[hs]>0
    row=dict(period=period, observed_key_slots=int(np.count_nonzero(observations)),
        conflicting_training_key_slots=int(np.count_nonzero(distinct>1)),
        training_repeated_slots=int(np.count_nonzero(observations>1)),
        train=score(tx^key[ts],ty),heldout=score(hx^key[hs],hy,eligible),
        heldout_unseen_key_slot_bytes=int(np.count_nonzero(~eligible)),
        random_control=score(hx^key[hs],random_actual,eligible))
    row['exact_training_consistency']=row['conflicting_training_key_slots']==0
    row['validated']=row['exact_training_consistency'] and row['heldout']['observations']>=4096 and row['heldout']['exact_match_percent']==100
    return row


def main():
    started=time.perf_counter()
    inventory=json.loads((ROOT/'reports/coverage-70/dump-inventory.json').read_text())
    pe=helpers.PE(ROOT/'benchmark-inputs/RobloxPlayerBeta-0.742.exe')
    assert pe.digest==helpers.EXPECTED
    qualified=[x for x in inventory['dumps'] if x.get('metadata_qualified_unique_captured_candidate_bytes',0)]
    train_row=max(qualified,key=lambda x:x['metadata_qualified_unique_captured_candidate_bytes'])
    training_ranges=[(int(x['start_rva'],16),int(x['end_rva'],16)) for x in train_row['metadata_qualified_unique_candidate_ranges']]
    relocation_exclusions=relocation_ranges(pe)
    train=code_pairs(train_row,pe,relocation_exclusions)
    heldouts=[]
    for row in qualified:
        if row['path']==train_row['path']:
            continue
        pairs=code_pairs(row,pe,relocation_exclusions+training_ranges)
        heldouts.append((len(pairs[0]),row,pairs))
    _,heldout_row,heldout=max(heldouts,key=lambda x:x[0])
    assert len(train[0])>4096 and len(heldout[0])>4096
    rng=np.random.default_rng(742)
    random_actual=rng.permutation(heldout[2])
    section=next(x for x in pe.sections if x['name']=='.text')
    shift=section['offset']-(section['va']-pe.base)
    result=dict(method='Original-file vs physically captured .text only; one coherent training snapshot; independent snapshot with every training RVA excluded; metadata-qualified build identity, original-file hash of snapshots unproven; no target execution or modification',
        original_sha256=pe.digest,training_dump=train_row['path'],training_dump_sha256=train_row['dump_sha256'],
        heldout_dump=heldout_row['path'],heldout_dump_sha256=heldout_row['dump_sha256'],
        training_bytes=len(train[0]),heldout_nonoverlapping_bytes=len(heldout[0]),
        relocation_exclusion_ranges=len(relocation_exclusions),
        exclusion_policy='Exclude original PE DIR64/HIGHLOW slots, and all overlapping training RVAs from independent heldout. Runtime-modified bytes not fully identifiable; conflicts disclosed.',
        uniform_independent_random_exact_byte_percent=100/256,
        random_control_policy='Seed742 permutation of heldout snapshot bytes preserves byte frequencies and destroys address correspondence',
        periodic_xor=[])
    for period in (1<<n for n in range(17)):
        row=periodic_probe(train,heldout,period,lambda x:x,random_actual)
        row['coordinate']='RVA'
        row['file_offset_coordinate_equivalent']=True
        row['equivalence_reason']=f'Only .text; file offsets equal RVA plus constant {shift}. This permutes periodic key slots and cannot change fit.'
        row['page_offset_coordinate_equivalent_for_periods_up_to_4096']=period<=4096
        result['periodic_xor'].append(row)
    _,tx,ty=train
    _,hx,hy=heldout
    counts=np.bincount(tx.astype(np.int64)*256+ty,minlength=65536).reshape(256,256)
    table=np.argmax(counts,axis=1).astype(np.uint8)
    seen=np.sum(counts,axis=1)>0
    result['fixed_byte_substitution']=dict(train=score(table[tx],ty),heldout=score(table[hx],hy,seen[hx]),
        random_control=score(table[hx],random_actual,seen[hx]),
        conflicting_input_byte_values=int(np.count_nonzero(np.count_nonzero(counts,axis=1)>1)),
        validated=False)
    # All byte-affine maps y=(a*x+b) mod256; fit training count table, heldout remains untouched.
    best=(-1,None,None)
    x=np.arange(256,dtype=np.int64)
    for a in range(256):
        output=(a*x[:,None]+np.arange(256)[None,:])&255
        agreements=counts[x[:,None],output].sum(axis=0)
        b=int(np.argmax(agreements))
        if int(agreements[b])>best[0]:
            best=(int(agreements[b]),a,b)
    _,a,b=best
    affine=((a*hx.astype(np.uint16)+b)&255).astype(np.uint8)
    result['byte_affine_map']=dict(a=a,b=b,train=dict(observations=len(tx),exact_byte_matches=best[0],exact_match_percent=100*best[0]/len(tx)),
        heldout=score(affine,hy),random_control=score(affine,random_actual),validated=False,
        invertible=a%2==1,warning='Constant maps can match frequent opcode/padding bytes without representing a transform')
    # Simple reversible fixed permutations within 2/4/8/16-byte aligned blocks.
    byte_shuffles=[]
    for width in (2,4,8,16):
        for style in ('reverse','rotate1'):
            matches=observations=0
            for rva,actual in zip(heldout[0],hy):
                rva=int(rva)
                within=rva%width
                other=rva-within+(width-1-within if style=='reverse' else (within+1)%width)
                source=pe.bytes(pe.base+other,1)
                if source:
                    observations+=1
                    matches+=source[0]==int(actual)
            byte_shuffles.append(dict(block_width=width,style=style,heldout=dict(observations=observations,exact_byte_matches=matches,
                exact_match_percent=100*matches/observations if observations else None),validated=False))
    result['fixed_byte_shuffle']=byte_shuffles
    result['transformation_validated']=any(x['validated'] for x in result['periodic_xor'])
    result['whole_image_recovery_ready']=False
    result['elapsed_seconds']=time.perf_counter()-started
    out=ROOT/'reports/coverage-70'
    (out/'transform-probe.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    best_period=max(result['periodic_xor'],key=lambda x:x['heldout']['exact_match_percent'] or 0)
    lines=['# Bounded static code transformation probes','',
        f"Used **{len(train[0]):,} captured training bytes** from `{pathlib.Path(train_row['path']).name}` and **{len(heldout[0]):,} heldout bytes** from `{pathlib.Path(heldout_row['path']).name}`. All training RVAs and original PE relocation slots are excluded from heldout. Inputs were read statically; no target execution, process reading, bypass, injection or rewritten image.",'',
        'The snapshots match timestamp, image size, fixed version and CodeView identity; zero checksums are unavailable. Exact original-file hash identity is unproven. Known code comes only from physically captured original-module `.text` ranges.','',
        '| XOR period | Conflicting training key slots | Training exact % | Heldout eligible bytes | Heldout exact % | Permuted-byte control % |',
        '|---:|---:|---:|---:|---:|---:|']
    for row in result['periodic_xor']:
        lines.append(f"| {row['period']} | {row['conflicting_training_key_slots']} | {row['train']['exact_match_percent']:.5f} | {row['heldout']['observations']} | {row['heldout']['exact_match_percent']:.5f} | {row['random_control']['exact_match_percent']:.5f} |")
    lines += ['',f"Best periodic XOR heldout agreement: **{best_period['heldout']['exact_match_percent']:.5f}%**, period {best_period['period']}. Uniform independent random exact-byte baseline is **0.390625%**; frequency-preserving randomized controls are shown above. Training overfit at large periods does not establish a repeating key.",'',
        f"Fixed byte substitution heldout agreement: **{result['fixed_byte_substitution']['heldout']['exact_match_percent']:.5f}%**; all {result['fixed_byte_substitution']['conflicting_input_byte_values']} input byte values map to conflicting output bytes. Best affine map heldout agreement: **{result['byte_affine_map']['heldout']['exact_match_percent']:.5f}%**; constants can simply match frequent opcodes. Simple fixed block shuffles are recorded in JSON.",'',
        'RVA and file-offset key indexing are equivalent up to a constant phase for the only tested section; page-offset indexing is equivalent for tested powers of two through 4096. No claim is made about cryptographic transformations, dynamically changing encodings or untested algorithms. Runtime modifications not identifiable from PE relocations can contribute conflicts.','',
        '**No tested transformation validated. Whole-image recovery is not ready.** Exact, consistent training and independent heldout agreement would be required before any wider-image transformation experiment. No decrypted image or key material was produced.']
    (out/'transform-probe.md').write_text('\n'.join(lines)+'\n',encoding='utf-8')
    print(json.dumps(dict(training_bytes=len(train[0]),heldout_bytes=len(heldout[0]),best_period=best_period['period'],
        best_heldout_percent=best_period['heldout']['exact_match_percent'],validated=result['transformation_validated'],elapsed_seconds=result['elapsed_seconds'])))


if __name__=='__main__':
    main()
