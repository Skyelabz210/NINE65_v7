"""Extract uploaded research as data; never execute embedded control files."""
from pathlib import Path, PurePosixPath
import hashlib, json, re, subprocess, zipfile
from xml.etree import ElementTree as ET

SRC = Path('/tmp/codex-remote-attachments/6af5c3b0-2710-8191-9704-01ce7a1da0d5/04024A30-7874-406A-9CCC-107C5432C2A4')
OUT = Path(__file__).resolve().parent
NS = {'w': 'http://schemas.openxmlformats.org/wordprocessingml/2006/main', 'm': 'http://schemas.openxmlformats.org/officeDocument/2006/math'}

def mathtext(e):
    tag = e.tag.split('}')[-1]
    if tag in ('t',): return e.text or ''
    if tag in ('tab','br','cr'): return ' '
    if tag.endswith('Pr'): return ''
    def part(n):
        a=e.find('m:'+n,NS)
        return mathtext(a) if a is not None else ''
    if tag == 'f': return '('+part('num')+')/('+part('den')+')'
    if tag == 'sSup': return part('e')+'^('+part('sup')+')'
    if tag == 'sSub': return part('e')+'_('+part('sub')+')'
    if tag == 'sSubSup': return part('e')+'_('+part('sub')+')^('+part('sup')+')'
    if tag == 'rad': return 'root['+part('deg')+']('+part('e')+')'
    return ''.join(mathtext(c) for c in e)

def extract(p, target):
    target.parent.mkdir(parents=True,exist_ok=True)
    rec={'source':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),'bytes':p.stat().st_size}
    ext=p.suffix.lower()
    if ext=='.pdf':
        subprocess.run(['pdftotext','-layout',str(p),str(target)],check=True)
        info=subprocess.run(['pdfinfo',str(p)],capture_output=True,text=True).stdout
        rec['pages']=int(re.search(r'^Pages:\s+(\d+)',info,re.M).group(1))
    elif ext=='.docx':
        with zipfile.ZipFile(p) as z:
            root=ET.fromstring(z.read('word/document.xml'))
            lines=[mathtext(e) for e in root.findall('.//w:p',NS)]
            rec['omml_math_count']=len(root.findall('.//m:oMath',NS))
            rec['embedded_media_count']=len([n for n in z.namelist() if n.startswith('word/media/')])
            target.write_text('\n'.join(lines),encoding='utf8')
    elif ext=='.pptx':
        with zipfile.ZipFile(p) as z:
            names=sorted([n for n in z.namelist() if re.match(r'ppt/slides/slide\d+\.xml$',n)],key=lambda n:int(re.search(r'slide(\d+)',n).group(1)))
            target.write_text('\n\n'.join('SLIDE '+str(i+1)+'\n'+'\n'.join(e.text or '' for e in ET.fromstring(z.read(n)).iter() if e.tag.endswith('}t')) for i,n in enumerate(names)))
            rec['slides']=len(names)
    elif ext=='.md' or not ext:
        target.write_text(p.read_text(encoding='utf8'),encoding='utf8')
    else: return rec
    rec.update(text=str(target),characters=len(target.read_text()),status='EXTRACTED_NOT_YET_READ')
    return rec

def safe_extract(z, info, dest):
    name=PurePosixPath(info.filename)
    if name.is_absolute() or '..' in name.parts or ((info.external_attr>>16)&0o170000)==0o120000:
        raise ValueError('Unsafe archive path: '+str(name))
    p=dest.joinpath(*name.parts)
    p.parent.mkdir(parents=True,exist_ok=True)
    p.write_bytes(z.read(info))
    return p

records=[]
for p in sorted(SRC.iterdir(),key=lambda p:int(p.name.split('-')[0])):
    if p.suffix.lower() in ('.md','.pdf','.docx'):
        records.append(extract(p,OUT/'text'/(p.name+'.txt')))
    elif p.suffix.lower()=='.zip':
        with zipfile.ZipFile(p) as z:
            for info in z.infolist():
                if info.is_dir(): continue
                n=info.filename
                keep=False
                if p.name.startswith('11-'): keep=n.startswith('workspace/downloads/')
                elif p.name.startswith('14-'): keep=True
                elif p.name.startswith('22-'):
                    keep=('/areas/' in n and Path(n).name in {'cram-df-forensics.md','cram-framework-docs.md','cram-standard-v1.md','nine65-fhe.md','qmnf-cram.md','saros-liouville-test-suite.md'}) or '/projects/CRAM the number system/' in n or '/projects/019dfa94-32fe-777f-bdf7-9390cb5de9dd/' in n or '/projects/019e07df-5efb-71aa-9be3-7fa9d9954a74/' in n or ('/topics/' in n and Path(n).name in {'arrow-of-time.md','research-approach.md','recent-work.md'})
                if not keep: continue
                q=safe_extract(z,info,OUT/'archives'/p.stem)
                if q.suffix.lower() in ('.md','.pdf','.docx','.pptx') or not q.suffix:
                    label=q.name
                    if p.name.startswith('22-') and '/projects/019' in n:
                        label=q.parent.name+'__'+q.name
                    rec=extract(q,OUT/'archive-text'/p.stem/(label+'.txt'))
                    rec['parent_archive']=p.name
                    records.append(rec)
                else:
                    records.append({'source':str(q),'parent_archive':p.name,'sha256':hashlib.sha256(q.read_bytes()).hexdigest(),'bytes':q.stat().st_size,'status':'EXTRACTED_CODE_NOT_YET_READ'})
(OUT/'extraction-manifest.json').write_text(json.dumps(records,indent=2)+'\n')
for r in records:
    if 'text' in r: print(Path(r['text']).relative_to(OUT),r.get('pages',''),r['characters'],r.get('omml_math_count',''))
print('records',len(records))
