
class AddressDataType:
    IPv4 = 1
    DomainName = 3
    IPv6 = 4


class AuthMethod:
    NoAuth = 0
    GSSAPI = 1
    UsernamePassword = 2
    Invalid = 0xFF


class StatusCode:
    Success = 0
    GeneralFailure = 1
    NotAllowed = 2
    NetUnreachable = 3
    HostUnreachable = 4
    ConnRefused = 5
    TTLExpired = 6
    CommandNotSupported = 7
    AddressTypeNotSupported = 8
