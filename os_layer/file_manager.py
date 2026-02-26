def read_binary(filepath, chunk_size=4096):
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            yield chunk


def write_binary(filepath, data):
    with open(filepath, "wb") as f:
        f.write(data)

