#!/usr/bin/env python3
# NAEF Combined Analysis: 8-Panel Figure (2 rows × 4 columns)
# Top row: Run 7 panels (a)-(d)
# Bottom row: Run 8 panels (e)-(h)

import numpy as np
from PIL import Image, ImageDraw, ImageFont

# Paths - adjust for your environment
RUN7_IMG = '../Campaign1_FragmentCountScaling/naef_run7_fig1.png'
RUN8_IMG = '../Campaign2_EpochIntervalScaling/naef_run8_fig1.png'

# For Google Colab:
# RUN7_IMG = '/content/drive/MyDrive/NAEF-plots/Run7_100Domain/naef_run7_fig1.png'
# RUN8_IMG = '/content/drive/MyDrive/NAEF-plots/Run8_80Domain/naef_run8_fig1.png'

img7 = np.array(Image.open(RUN7_IMG))
img8 = np.array(Image.open(RUN8_IMG))

def find_row_split(img):
    """Find the row separator closest to the vertical center."""
    h = img.shape[0]
    mid = h // 2
    bands = []
    in_band = False
    band_start = 0
    for y in range(h):
        if img[y, :, :3].mean() > 253:
            if not in_band:
                in_band = True
                band_start = y
        else:
            if in_band:
                w = y - band_start
                if w > 5 and band_start > 100:
                    bands.append((band_start, y, w))
                in_band = False
    bands.sort(key=lambda b: abs((b[0]+b[1])//2 - mid))
    return bands[0][0], bands[0][1]

def extract_panels(img):
    h, w = img.shape[:2]
    split_top, split_bot = find_row_split(img)
    mid_w = w // 2
    return [
        img[:split_top, :mid_w],
        img[:split_top, mid_w:],
        img[split_bot:, :mid_w],
        img[split_bot:, mid_w:],
    ]

panels7 = extract_panels(img7)
panels8 = extract_panels(img8)

# Resize panels per row
target_w = min(p.shape[1] for p in panels7 + panels8)

def resize_panel(p, th, tw):
    return np.array(Image.fromarray(p).resize((tw, th), Image.LANCZOS))

h7_target = max(p.shape[0] for p in panels7)
panels7 = [resize_panel(p, h7_target, target_w) for p in panels7]

h8_target = max(p.shape[0] for p in panels8)
panels8 = [resize_panel(p, h8_target, target_w) for p in panels8]

# Panel titles (max 3 words)
titles7 = ['(a) KDA Cost', '(b) Security-Performance Tradeoff', '(c) VDA Cost', '(d) Epoch Lifecycle']
titles8 = ['(e) KDA Cost', '(f) Security-Performance Tradeoff', '(g) VDA Cost', '(h) Epoch Lifecycle']

# Create title bars
TITLE_H = 50
try:
    font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 30)
except:
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", 30)
    except:
        font = ImageFont.load_default()

def make_title_bar(title, width):
    bar = Image.new('RGBA', (width, TITLE_H), (255, 255, 255, 255))
    draw = ImageDraw.Draw(bar)
    bbox = draw.textbbox((0, 0), title, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    x = (width - tw) // 2
    y = (TITLE_H - th) // 2 - 2
    draw.text((x, y), title, fill=(0, 0, 0, 255), font=font)
    return np.array(bar)

def add_titles_below(panels, titles):
    result = []
    for p, t in zip(panels, titles):
        title_bar = make_title_bar(t, p.shape[1])
        # Match channel count
        if p.shape[2] == 3 and title_bar.shape[2] == 4:
            title_bar = title_bar[:, :, :3]
        elif p.shape[2] == 4 and title_bar.shape[2] == 3:
            alpha = np.full((*title_bar.shape[:2], 1), 255, dtype=np.uint8)
            title_bar = np.concatenate([title_bar, alpha], axis=2)
        result.append(np.vstack([p, title_bar]))
    return result

panels7 = add_titles_below(panels7, titles7)
panels8 = add_titles_below(panels8, titles8)

# Build rows
row7 = np.hstack(panels7)
row8 = np.hstack(panels8)

# 20px white separator between rows
sep = np.full((20, row7.shape[1], row7.shape[2]), 255, dtype=np.uint8)
combined = np.vstack([row7, sep, row8])

Image.fromarray(combined).save('naef_combined_analysis.png')
print(f"Saved naef_combined_analysis.png ({combined.shape[1]}×{combined.shape[0]})")
