# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
