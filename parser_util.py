def value_convert(x):
    """
    This function attempt to decode the bytes value with ascii.
    If that's not possible then simply return the hex value
    :param x: The bytes input
    :return: The ascii or hex representation of the bytes
    """
    try:
        return x.decode("ascii")
    except UnicodeDecodeError:
        return x.hex()


def byteslist_to_int(byteslist):
    """
    This function takes a list of bytes and convert the value to a base 10 int
    :param byteslist: the list of bytes
    :return: integer of the list of bytes
    """
    holder = bytes()
    for v in byteslist:
        holder += v
    return int.from_bytes(holder, byteorder='big')