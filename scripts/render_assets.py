"""Render GitHub preview assets from sanitized local policy validation output."""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont


ROOT = Path(__file__).resolve().parents[1]
ASSETS = ROOT / "assets"
ASSETS.mkdir(exist_ok=True)
SANS = "/System/Library/Fonts/Helvetica.ttc"
MONO = "/System/Library/Fonts/Menlo.ttc"


def font(path: str, size: int) -> ImageFont.FreeTypeFont:
    return ImageFont.truetype(path, size=size)


def rounded(draw: ImageDraw.ImageDraw, box: tuple[int, int, int, int], radius: int, fill: str) -> None:
    draw.rounded_rectangle(box, radius=radius, fill=fill)


def terminal() -> None:
    image = Image.new("RGB", (1600, 760), "#0b1020")
    draw = ImageDraw.Draw(image)
    rounded(draw, (70, 70, 1530, 690), 26, "#111827")
    rounded(draw, (70, 70, 1530, 148), 26, "#1f2937")
    draw.rectangle((70, 122, 1530, 148), fill="#1f2937")
    for index, color in enumerate(("#fb7185", "#fbbf24", "#34d399")):
        draw.ellipse((106 + index * 34, 98, 126 + index * 34, 118), fill=color)
    title = font(SANS, 27)
    code = font(MONO, 30)
    small = font(SANS, 23)
    draw.text((220, 96), "pg-kms-gateway · policy validation", font=title, fill="#e5e7eb")
    command = [
        "$ pg-kms-gateway policy-check \\",
        "    --policy examples/policy.yaml",
    ]
    y = 240
    for line in command:
        draw.text((124, y), line, font=code, fill="#d1d5db")
        y += 54
    draw.text((124, 430), 'valid policy "customer_pii": 3 protected columns,', font=code, fill="#6ee7b7")
    draw.text((124, 484), 'key domain "production.customer-pii"', font=code, fill="#6ee7b7")
    draw.text((124, 620), "Real output from the policy compiler used at gateway startup.", font=small, fill="#9ca3af")
    image.save(ASSETS / "policy-check.png", optimize=True)


def social() -> None:
    image = Image.new("RGB", (1280, 640), "#0b1020")
    draw = ImageDraw.Draw(image)
    for x, y, r, color in (
        (1030, 135, 155, "#172554"), (1142, 247, 96, "#1e3a8a"),
        (920, 452, 214, "#0f766e"), (1120, 490, 136, "#164e63"),
    ):
        draw.ellipse((x-r, y-r, x+r, y+r), fill=color)
    brand = font(SANS, 28)
    name = font(SANS, 70)
    body = font(SANS, 33)
    draw.text((92, 80), "VENDORA INFRASTRUCTURE", font=brand, fill="#93c5fd")
    draw.text((88, 178), "pg-kms-gateway", font=name, fill="#f8fafc")
    draw.text((92, 292), "Policy-driven PostgreSQL field", font=body, fill="#d1d5db")
    draw.text((92, 342), "encryption backed by KMS.", font=body, fill="#d1d5db")
    rounded(draw, (92, 452, 278, 507), 16, "#1d4ed8")
    draw.text((116, 464), "PostgreSQL v3", font=font(SANS, 22), fill="#eff6ff")
    rounded(draw, (300, 452, 535, 507), 16, "#065f46")
    draw.text((324, 464), "KMS envelope keys", font=font(SANS, 22), fill="#ecfdf5")
    rounded(draw, (557, 452, 820, 507), 16, "#312e81")
    draw.text((581, 464), "Policy fails closed", font=font(SANS, 22), fill="#eef2ff")
    draw.text((92, 563), "github.com/vendora-bit/pg-kms-gateway", font=font(MONO, 22), fill="#94a3b8")
    image.save(ASSETS / "social-preview.png", optimize=True)


if __name__ == "__main__":
    terminal()
    social()

