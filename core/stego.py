from PIL import Image

DELIMITER = b"====END===="


def hide_data_in_image(image_path, secret_data, output_path):
    img = Image.open(image_path)

    # Ensure image is in RGBA (safe for all PNGs)
    img = img.convert("RGBA")
    pixels = list(img.getdata())

    secret_data += DELIMITER
    binary = ''.join(format(byte, '08b') for byte in secret_data)

    new_pixels = []
    bit_index = 0

    for pixel in pixels:
        r, g, b, a = pixel

        if bit_index < len(binary):
            r = (r & ~1) | int(binary[bit_index])
            bit_index += 1

        new_pixels.append((r, g, b, a))

    img.putdata(new_pixels)
    img.save(output_path)


def extract_data_from_image(image_path):
    img = Image.open(image_path).convert("RGBA")
    pixels = list(img.getdata())

    bits = ""
    for pixel in pixels:
        bits += str(pixel[0] & 1)

    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        data.append(int(byte, 2))

        if data.endswith(DELIMITER):
            return data[:-len(DELIMITER)]

    raise ValueError("No hidden data found")
