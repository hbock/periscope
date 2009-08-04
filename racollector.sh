#!/bin/bash
# Periscope - Network auditing tool
# Copyright (C) 2009 Harry Bock <harry@oshean.org>

# This file is part of Periscope.

# periscope is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

# periscope is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with periscope; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

# Simple script wrapping rabins/rasplit for use with Periscope.
# Syntax:
#   racollector tinderbox.oshean.lan 1h "reports/hourly/h.%Y%m%d-%H"
#
# Called from Lisp using EXECUTE-COMMAND.
# To stop, simply raise SIGINT to this process.

rabins=${PREFIX}rabins
rasplit=${PREFIX}rasplit

error_message()
{
    [ -n "$1" ] && echo $1 >&2
}

usage()
{
    error_message "Usage: $0 argus-server time-period output-format"
    exit 1
}

if [ ! -x $rabins ] && [ ! -x $rasplit ]; then
    error_message "Error: rabins/rasplit not found. Please install argus-clients!"
    exit 1
fi

if [ -z "$1" ] || [ -z "$2" ] || [ -z "$3" ]; then usage; fi

$rabins -S $1 -M time $2 -B 20s -w - | $rasplit -M time $2 -w "$3"
