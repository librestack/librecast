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

Comments, questions, suggestions, bug reports, and patches welcome.  See CONTRIBUTING.md

Brett Sheffield `<brett@librecast.net>`


### Website

https://librecast.net/


### IRC channel

`#librecast` on freenode.net

If you have a question, please be patient. An answer might take a few hours
depending on time zones and whether anyone on the team is available at that
moment.  Feel free to raise an issue on the bug tracker.


### Documentation

You can probably figure most things out by looking at the tests and header
files.  There are code samples in `test/` that will show you how to do the most
common things.

Lets run through the basic concepts:


#### Getting started

In C, we'll need a header.  Just the first one will do:
```
#include <librecast.h>        /* include all functions */

/* or */

#include <librecast/net.h>    /* just the network (multicast) bits */
#include <librecast/db.h>     /* local database functions */
#include <librecast/netdb.h>  /* remote (multicast) database functions */

/* or, if you just need to refer to a Librecast type in another project */

#include <librecast/types.h>  /* Librecast type declarations */

```

Everything starts with a Librecast Context:

```
lc_ctx_t *lctx;
lctx = lc_ctx_new();

lc_ctx_free(lctx); /* free it when done */
```

Then you probably want a Librecast Socket:
```
lc_socket_t *sock;
sock = lc_socket_new(lctx);

/* you can set whatever underlying socket options you want, such as TTL and LOOPBACK */
/* if you want to receive your own packets, you'll need this: */
lc_socket_setopt(sock, IPV6_MULTICAST_LOOP, &opt, sizeof(opt);

lc_socket_close(sock); /* close this when done */
```

Sockets aren't much use without Channels.  A Channel, in Librecast terms,
represents a multicast group.  You create channels, bind them to sockets, and
join those channels.

```
lc_channel_t *chan;
chan = lc_channel_new(lctx, "example.com");

lc_channel_bind(sock, chan)  /* bind the channel to a socket */
lc_channel_bind(sock, chan2) /* you can bind more than one */

lc_channel_join(chan) /* we need to join a channel if we want to listen */
/* no need to join if we only want to send */

lc_channel_free(chan); /* free when done */
```

To listen on a channel and process messages, we can either use a synchronous
call, or asyncronous with callbacks:

```
void callback_msg(lc_message_t *msg) {
	/* do something with message */
}

void callback_err() {
	/* handle error */
}

/* this starts a listening thread, with callbacks */
lc_socket_listen(sock, callback_msg, callback_err);

/* or, we can do a blocking recv */
size_t bytes = lc_msg_recv(sock, &msg);     /* blocking recv */

```

Now lets create a message and send it:

```
char data[] = "life, the universe, everything";
lc_message_t msg;
lc_msg_init_data(&msg, data, strlen(data), NULL, NULL);
lc_msg_send(chan, &msg);
```


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

## Questions, Bug reports, Feature Requests

New issues can be raised at:

https://github.com/librestack/librecast/issues

It's okay to raise an issue to ask a question.  You can also email or ask on
IRC.

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
