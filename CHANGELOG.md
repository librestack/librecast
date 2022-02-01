# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- lc_tuntap_create() - create TUN/TAP sockets
- lc_channel_random() - create random channel
- tracking group joins per socket when IPV6_MULTICAST_ALL not defined

This means ALL packets for ALL multicast groups joined by ANY PROCESS owned by ANY USER will be received by a socket by default. That's ... surprising. And not the behaviour we want.

Librecast needs to track group joins per socket and drop any packets that aren't expected on that socket.

### Fixed

- use non-default channel port if specified on recv

## [0.4.4] - 2021-06-05

### Added
- lc_bridge_add() / lc_bridge_del()
- lc_tap_create()
- lc_link_set() - bring up / tear down network interfaces
- lc_bridge_addif() / lc_bridge_delif()
- fallback interface code for unsupported platforms
- lc_channel_send() / lc_socket_recv() - raw channel/socket send/recv functions
- lc_channel_sendmsg() / lc_socket_recvmsg()
- lc_socket_bind() - join on all multicast-capable interfaces, or bound socket ifx
- lc_socket_send() - send to all channels bound to socket
- lc_socket_sendmsg()
- lc_socket_ttl() - set socket TTL

### Changed

- License changed to GPL-2.0 or GPL-3.0 (dual licenced)
- Update README - irc channel moved to Libera.chat
- Default hashing function changed to BLAKE2B from libsodium
- libs/Makefile: Fix targets when building without blake3
- split bridge/interface code by O/S
- remove -std=gnu99 from NetBSD build - required for NetBSD 7, no longer reqd for 9.

### Fixed
- lc_msg_recv(): add cancellation point before recvmsg() - hangs on NetBSD without this.
- lc_channel_bind(): set SO_REUSEPORT if defined - required on NetBSD to prevent "address
    already in use" errors.

## [0.4.3] - 2021-03-09

### Fixed

- Use IPV6_JOIN_GROUP / IPV6_LEAVE_GROUP in preference to obsolete IPV6_ADD_MEMBERSHIP / IPV6_DROP_MEMBERSHIP
- Fix tempfile creation for tests on NetBSD.
- Sort uses of "wildcard" in Makefile to make ordering of files predictible and avoid potential reproducibility issues.
- Makefile fixes for NetBSD - replace call to ldconfig

## [0.4.2] - 2021-03-06

### Added

`<librecast/crypto.h>`
- hash_generic()
- hash_generic_key()
- hash_init()
- hash_update()
- hash_final()
- hash_hex_debug()
- hash_bin2hex()

### Changed

- Changed default hashing function to BLAKE3. This is faster and and has similar
    security properties to BLAKE2B from libsodium.  Build with `make USE_LIBSODIUM=1` to
    use BLAKE2B instead.

### Fixed

- Support DESTDIR when installing docs.
- Pass LIBDIR to ldconfig in the install target.
- Building without libsodium.
- Ensure a clean build before running single tests.
- Work around bugs in gcc and glibc to fix test malloc

## [0.4.1] - 2021-03-04

### Added
- Instructions for Ubuntu to install prerequisite libsodium-dev (Esther Payne)

### Fixed
- Remove references to obsolete libraries in test Makefile (Esther Payne)

## [0.4.0] - 2021-03-04

### Added
- CHANGELOG.md (this file)
- test/falloc.c - failing malloc checker so we can force memory allocation
    failures in testing.
- libsodium dependency (required for hashing)
- valgrind.h added to `test/` so we can skip tests that don't play nicely with
    valgrind.

### Changed
- The base multicast networking API has been reviewed, extensively refactored and simplified.
- Functions were reordered more logically, grouping functions that call each
    other close together to improve efficiency.
- Network interface indexes are now unsigned values everywhere.
- Changes to the Channels API. lc_channel_init() now takes sockaddr_in6 so
    address and port can be directly specified and to save much converting back
    and forth between string and binary addresses. All calls to getaddrinfo()
    and use of struct addrinfo have been removed - there's really no need for
    this in multicast code.
- Sockets and Channels are now inserted at the head of their lists. This is
    quicker, simplifies the code, and makes finding the most recently added faster.
- SHA1 hash replaced with BLAKE2B from libsodium.
- Renumbered error codes as negative.
- lc_msg_logger() - optional message logging implemented as a function pointer

### Removed
- The experimental database API has been removed completely for now, as it was intertwined with the network code. The core multicast code should not be require any database functionality or dependencies. This will be rewritten in the next milestone.
- All logging has been removed. This is a library - we return error codes in serene silence and let the programmer decide what to do with them.
- Removed some pointless argument checking in various API calls. A careless
    programmer won't be checking the return codes anyway. In some cases these
    have been replaced with assert()s to catch accidental API misuse.
- OpenSSL dependency
- libbridge dependency
- Linux-specific headers
- Removed obsolete tests.

### Fixed
- docs (man pages) are now installed with `make install`


## [0.3.0] - 2020-09-05

### Added
- The code now compiles using either gcc or clang.  There is a "make clang" target in the Makefile.
- Added test runner and a set of test modules to the project to exercise
all the main functions, including common error conditions.  This will continue
to be added to as I have adopted test driven development for the project.

`make test` runs all the tests.
`make check` runs all the tests using valgrind to do leak checking and dynamic
analysis.

`make 0000-0004.test` runs a single test.
`make 0000-0004.check` runs a single test with valgrind
`make 0000-0004.debug` runs a single test with the gdb debugger
`make sparse` compiles the project using cgcc (the sparse static analyser)
`make clang` builds the project using clang
`make coverity` builds the project using the coverity static analyser, creating
a librecast.tgz ready to upload to Coverity Scan for analysis.

### Changed

- Split the library into three separate parts and removed some redundant code.
- There are now separate headers and shared libraries for IPv6 Multicast messaging (net), local database commands and querying (lsdb) and remote (multicast) database commands (lcdb)
