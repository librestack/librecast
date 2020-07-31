# Librecast - Distributed Applications with IPv6 Multicast

<a href="https://opensource.org"><img height="150" align="right" src="https://opensource.org/files/OSIApprovedCropped.png" alt="Open Source Initiative Approved License logo"></a>

![Librecast Logo](https://secure.gravatar.com/avatar/52295d18e59ef41aeac21f3745250288?s=200)

<a href="https://scan.coverity.com/projects/librestack-librecast">
  <img alt="Coverity Scan Build Status"
       src="https://scan.coverity.com/projects/21543/badge.svg"/>
</a>

## README

Librecast is a project to provide fast, efficient and scalable
communication by leveraging IPv6 multicast.

Features:
 * IPv6 and multicast supported from the outset
 * light, fast and simple design
 * scalability a design consideration from the outset

There are separate headers and shared libraries for:
 * IPv6 Multicast messaging
 * local database commands and querying
 * remote (multicast) database commands

The library will be extended soon to provide transitional support and tunnelling
such that multicast can function as an overlay network until native multicast
becomes more widely available.

### Website

https://librecast.net/

### IRC channel

`#librecast` on freenode.net

### Installing

See INSTALL.md

### Compilation and Testing Options

The code compiles using either gcc or clang.  There is a `make clang` target.
The default is whatever your default CC is.

#### Testing
A test runner and a set of test modules exercise the main functions, including
common error conditions.

Logs are output in the test directory (the tests tell you where).
`test/lastlog.log` is a symlink to the logs from the last test run.

`make test` runs all tests.
`make check` runs all tests using valgrind to do leak checking and dynamic
analysis.

Other useful make targets:
`make 0000-0004.test` run a single test.
`make 0000-0004.check` run a single test with valgrind
`make 0000-0004.debug` runs a single test with the gdb debugger
`make sparse` compiles the project using cgcc (the sparse static analyser)
`make clang` builds the project using clang
`make coverity` builds the project using the coverity static analyser, creating
a librecast.tgz ready to upload to Coverity Scan for analysis.

The code is available here:

https://github.com/librestack/librecast

Makes scalable, secure network programming available easily in any supported
language.  Initial support is for C, with python, perl, rust, golang and other
wrappers following as time and interest permits.  Feel free to contribute a
wrapper.

Comments, questions, suggestions, bug reports, and patches welcome.  See CONTRIBUTING.md

Brett Sheffield `<brett@librecast.net>`

<hr />

<p class="bigbreak">
This project was funded through the <a href="https://nlnet.nl/discovery"> NGI0 Discovery </a> Fund, a fund established by NLnet with financial support from the European
Commission's <a href="https://ngi.eu">Next Generation Internet</a> programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 825322. *Applications are still open, you can <a href="https://nlnet.nl/propose">apply today</a>*
</p>

<p>
  <a href="https://nlnet.nl/project/LibrecastLive/">
      <img width="250" src="https://nlnet.nl/logo/banner.png" alt="Logo NLnet: abstract logo of four people seen from above" class="logocenter" />
  </a>
  <a href="https://ngi.eu/">
      <img width="250" align="right" src="https://nlnet.nl/image/logos/NGI0_tag.png" alt="Logo NGI Zero: letterlogo shaped like a tag" class="logocenter" />
  </a>
</p>
