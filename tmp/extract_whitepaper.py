import re
import zlib

with open('Qeuph_QUH_Whitepaper.pdf', 'rb') as f:
    data = f.read()

def get_obj(num):
    m = re.search(rb'%d\s+0\s+obj(.*?)endobj' % num, data, re.DOTALL)
    if not m: return None
    c = m.group(1)
    sm = re.search(rb'stream[\r\n]+(.*?)[\r\n]+endstream', c, re.DOTALL)
    if not sm: return c
    raw = sm.group(1)
    try: raw = zlib.decompress(raw)
    except: pass
    return raw

def parse_cmap(cmap_bytes):
    mapping = {}
    for line in cmap_bytes.splitlines():
        line = line.strip()
        m = re.match(rb'<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>', line)
        if m:
            src = int(m.group(1), 16)
            dst = chr(int(m.group(2), 16))
            mapping[src] = dst
        m2 = re.match(rb'<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>\s+<([0-9a-fA-F]+)>', line)
        if m2:
            s_start = int(m2.group(1), 16)
            s_end = int(m2.group(2), 16)
            d_start = int(m2.group(3), 16)
            for s in range(s_start, s_end + 1):
                mapping[s] = chr(d_start + (s - s_start))
    return mapping

font_objs = {}
for m in re.finditer(rb'(\d+)\s+0\s+obj(.*?)endobj', data, re.DOTALL):
    obj_id = int(m.group(1))
    content = m.group(2)
    if b'/Type /Font' in content or b'/Type/Font' in content:
        tu = re.search(rb'/ToUnicode\s+(\d+)\s+0\s+R', content)
        if tu:
            cmap_obj = int(tu.group(1))
            cmap_bytes = get_obj(cmap_obj)
            if cmap_bytes:
                font_objs[obj_id] = parse_cmap(cmap_bytes)

pages = []
for m in re.finditer(rb'(\d+)\s+0\s+obj(.*?)endobj', data, re.DOTALL):
    obj_id = int(m.group(1))
    content = m.group(2)
    if b'/Type /Page' in content and b'/Contents' in content:
        c_ref = re.search(rb'/Contents\s+(\d+)\s+0\s+R', content)
        if c_ref:
            pages.append((obj_id, int(c_ref.group(1)), content))

master_map = {}
for cmap in font_objs.values():
    master_map.update(cmap)

def decode_bytes(s, font_map):
    dec = []
    i = 0
    while i < len(s):
        if s[i:i+1] == b'\\':
            oct_m = re.match(rb'\\([0-7]{1,3})', s[i:])
            if oct_m:
                val = int(oct_m.group(1), 8)
                dec.append(font_map.get(val, chr(val) if 32 <= val < 127 else ' '))
                i += len(oct_m.group(0))
                continue
            elif i + 1 < len(s):
                ch = s[i+1]
                dec.append(chr(ch))
                i += 2
                continue
        val = s[i]
        dec.append(font_map.get(val, chr(val) if 32 <= val < 127 else ' '))
        i += 1
    return ''.join(dec)

full_pages_text = []
for p_idx, (page_obj_id, cont_id, page_def) in enumerate(pages):
    cont_bytes = get_obj(cont_id)
    if not cont_bytes:
        continue
    
    page_fonts = {}
    for fm in re.finditer(rb'/(\w+)\s+(\d+)\s+0\s+R', page_def):
        f_name = fm.group(1).decode()
        f_id = int(fm.group(2))
        if f_id in font_objs:
            page_fonts[f_name] = font_objs[f_id]
            
    cur_font_map = master_map
    page_text = []
    
    tokens = re.findall(rb'(/F\d+|/TT\d+|/C\d+)\s+[\d\.]+\s+Tf|\[(.*?)\]\s*TJ|\((.*?)\)\s*Tj|\((.*?)\)\s*\'', cont_bytes, re.DOTALL)
    for font_set, tj_arr, tj_str1, tj_str2 in tokens:
        if font_set:
            fname = font_set.decode().lstrip('/')
            cur_font_map = page_fonts.get(fname, master_map)
        elif tj_str1 or tj_str2:
            s = tj_str1 or tj_str2
            page_text.append(decode_bytes(s, cur_font_map))
        elif tj_arr:
            sub_strs = re.findall(rb'\((.*?)\)|(-?\d+)', tj_arr, re.DOTALL)
            for sub_str, spacing in sub_strs:
                if spacing:
                    if float(spacing) < -150:
                        page_text.append(' ')
                elif sub_str:
                    page_text.append(decode_bytes(sub_str, cur_font_map))
    
    pt = ''.join(page_text)
    full_pages_text.append(f'=== PAGE {p_idx+1} ===\n' + pt)

complete_doc = '\n\n'.join(full_pages_text)
with open('whitepaper_decoded.txt', 'w') as f:
    f.write(complete_doc)

print('Successfully decoded', len(full_pages_text), 'pages, total chars:', len(complete_doc))
