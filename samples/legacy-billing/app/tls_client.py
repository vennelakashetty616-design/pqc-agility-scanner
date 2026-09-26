import ssl


def context() -> ssl.SSLContext:
    return ssl.SSLContext(ssl.PROTOCOL_TLSv1)
