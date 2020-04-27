/* SPDX-License-Identifier: GPL-3.0-or-later
* Copyright (c) 2012-2020 Brett Sheffield <bacs@librecast.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (see the file COPYING in the distribution).
 * If not, see <http://www.gnu.org/licenses/>.
 */

# Librecast - Distributed Applications with IPv6 Multicast

<a href="https://opensource.org"><img height="150" align="right" src="https://opensource.org/files/OSIApprovedCropped.png" alt="Open Source Initiative Approved License logo"></a>

![Librecast Logo](https://secure.gravatar.com/avatar/52295d18e59ef41aeac21f3745250288?s=250)

## README

Librecast is an *experimental* project to provide fast, efficient and scalable
communication between servers by leveraging IPv6 multicast.

NB: this is a WORK IN PROGRESS and is INCOMPLETE.

Features:
 * IPv6 and multicast supported from the outset
 * light, fast and simple design
 * scalability a design consideration from the outset

Intended to be used called from client libraries to make scalable, secure
network programming available easily in any supported language.  Initial 
support will be for C, with python, perl and other wrappers following as time
and interest permits.

At the core of the design is the concept of fetching variables remotely from
one or more network nodes and acting on the results programmatically.  This
makes writing, say, monitoring or configuration management logic simple in any
supported language.

Essentially this enables us to utilise the actor model of distributed
programming, backed by the advantages of IPv6 multicast by default, and
degrading gracefully through a series of fallback options to improve
reachability in cases where the default mode is unavailable.

There are plenty of other tools available for monitoring, configuration
management etc and several network programming frameworks.  However, IPv6 is
often an afterthought, if it is supported at all.  Multicast is rarely used,
even when communicating one to many.  Often heavyweight unicast TCP connections
are established to communicate the same information to many servers
simultaenously.  Security is sometimes considered an optional extra.  Some are
built in higher level languages I'm not fond of, and which I feel have little
place in low-level systems programming.  Perhaps I'm just getting grumpier as I
get older.

Anyway, I thought it would be interesting to build something from scratch and
see whether this approach has any merit.  I'll put this out there in case
anyone else finds it useful.  Comments, questions, suggestions, bug reports,
and patches all welcome.

Brett Sheffield `<brett@gladserv.com>`
