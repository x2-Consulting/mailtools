import io
import re
from xml.dom.minidom import parseString


def convert_to_bimi_svg(input_bytes: bytes, filename: str = '') -> dict:
    """Convert SVG or raster image to BIMI-compliant SVG 1.2 Tiny P/S."""
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext in ('png', 'jpg', 'jpeg', 'gif', 'webp'):
        return _convert_raster(input_bytes)
    return _clean_svg(input_bytes)


def _clean_svg(svg_bytes: bytes) -> dict:
    warnings = []
    errors = []

    try:
        svg_text = svg_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return {'svg': None, 'warnings': [], 'errors': [f'Could not decode file: {e}'], 'valid': False}

    try:
        dom = parseString(svg_text.encode('utf-8'))
    except Exception as e:
        return {'svg': None, 'warnings': [], 'errors': [f'Invalid XML: {e}'], 'valid': False}

    root = dom.documentElement
    local = root.localName or root.tagName
    if local != 'svg':
        return {'svg': None, 'warnings': [], 'errors': ['Root element is not <svg>'], 'valid': False}

    # Fix version / baseProfile
    old_ver = root.getAttribute('version')
    if old_ver != '1.2':
        warnings.append(f'SVG version updated to "1.2" (was {repr(old_ver) if old_ver else "unset"})')
        root.setAttribute('version', '1.2')

    old_bp = root.getAttribute('baseProfile')
    if old_bp != 'tiny-ps':
        warnings.append(f'baseProfile set to "tiny-ps" (was {repr(old_bp) if old_bp else "unset"})')
        root.setAttribute('baseProfile', 'tiny-ps')

    if not root.getAttribute('xmlns'):
        root.setAttribute('xmlns', 'http://www.w3.org/2000/svg')

    # Ensure square viewBox
    viewbox = root.getAttribute('viewBox')
    if not viewbox:
        w = _parse_num(root.getAttribute('width') or '100')
        h = _parse_num(root.getAttribute('height') or '100')
        viewbox = f'0 0 {w} {h}'
        root.setAttribute('viewBox', viewbox)
        warnings.append(f'Added viewBox="{viewbox}" derived from width/height')

    vb = viewbox.strip().replace(',', ' ').split()
    if len(vb) == 4:
        try:
            vb_w, vb_h = float(vb[2]), float(vb[3])
            if abs(vb_w - vb_h) > 0.5:
                side = max(vb_w, vb_h)
                root.setAttribute('viewBox', f'{vb[0]} {vb[1]} {side} {side}')
                warnings.append(f'viewBox made square: {vb_w}x{vb_h} -> {side}x{side} (BIMI requires square logo)')
        except ValueError:
            pass

    root.setAttribute('width', '100%')
    root.setAttribute('height', '100%')

    # Remove disallowed elements
    DISALLOWED = ['script', 'animate', 'animateMotion', 'animateTransform',
                  'animateColor', 'set', 'foreignObject', 'a']
    removed = []
    for tag in DISALLOWED:
        nodes = dom.getElementsByTagName(tag)
        if nodes.length:
            removed.append(f'{tag}({nodes.length})')
            for node in list(nodes):
                if node.parentNode:
                    node.parentNode.removeChild(node)
    if removed:
        warnings.append(f'Removed disallowed elements: {", ".join(removed)}')

    # Remove external href references
    ext_removed = []
    for node in _all_elements(dom):
        for attr in ('href', 'xlink:href'):
            val = node.getAttribute(attr)
            if val and (val.startswith('http') or val.startswith('//')):
                node.removeAttribute(attr)
                ext_removed.append(f'<{node.tagName}> {attr}')
    if ext_removed:
        warnings.append(f'Removed external refs: {", ".join(ext_removed[:5])}')

    # Remove <style> blocks with @import or external url()
    for style in list(dom.getElementsByTagName('style')):
        css = (style.firstChild.nodeValue or '') if style.firstChild else ''
        if '@import' in css or re.search(r'url\s*\(\s*["\']?https?://', css):
            style.parentNode.removeChild(style)
            warnings.append('Removed <style> block with @import or external url()')

    if not dom.getElementsByTagName('title').length:
        warnings.append('No <title> element — add <title>Your Brand Name</title> for accessibility')

    try:
        out = dom.toxml(encoding='UTF-8')
        svg_out = out if isinstance(out, bytes) else out.encode('utf-8')
        return {'svg': svg_out, 'warnings': warnings, 'errors': errors, 'valid': True}
    except Exception as e:
        return {'svg': None, 'warnings': warnings, 'errors': [f'Serialisation error: {e}'], 'valid': False}


def _convert_raster(img_bytes: bytes) -> dict:
    try:
        from PIL import Image
        import base64
        img = Image.open(io.BytesIO(img_bytes)).convert('RGBA')
        w, h = img.size
        side = max(w, h)
        sq = Image.new('RGBA', (side, side), (255, 255, 255, 0))
        sq.paste(img, ((side - w) // 2, (side - h) // 2))
        buf = io.BytesIO()
        sq.save(buf, 'PNG')
        b64 = base64.b64encode(buf.getvalue()).decode()
        svg = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
               f'<svg version="1.2" baseProfile="tiny-ps" xmlns="http://www.w3.org/2000/svg" '
               f'viewBox="0 0 {side} {side}" width="100%" height="100%">\n'
               f'  <title>Logo</title>\n'
               f'  <image width="{side}" height="{side}" href="data:image/png;base64,{b64}"/>\n'
               f'</svg>')
        return {
            'svg': svg.encode('utf-8'),
            'warnings': [
                'Raster image embedded in SVG wrapper — NOT fully BIMI-compliant',
                'BIMI requires a native vector SVG. This may not pass BIMI validators.',
                'For best results, export your logo as a proper SVG from a vector editor.',
            ],
            'errors': [],
            'valid': False,
        }
    except ImportError:
        return {'svg': None, 'warnings': [], 'errors': ['Pillow not installed'], 'valid': False}
    except Exception as e:
        return {'svg': None, 'warnings': [], 'errors': [f'Raster conversion failed: {e}'], 'valid': False}


def _parse_num(val: str) -> float:
    try:
        return float(re.sub(r'[^0-9.]', '', val) or '100')
    except ValueError:
        return 100.0


def _all_elements(dom):
    result = []
    queue = [dom.documentElement]
    while queue:
        node = queue.pop()
        result.append(node)
        for i in range(node.childNodes.length):
            child = node.childNodes.item(i)
            if child.nodeType == 1:
                queue.append(child)
    return result
