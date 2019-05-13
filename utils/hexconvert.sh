#!/bin/sh
#
# Copyright (C) 2019  Red Hat, Inc.
# Author(s):  David Shea <dshea@redhat.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

# The input format is a comma-separated list of hex bytes, like the output
# from rpmdump.c

offset=0
output=""
while read -r input ; do
    while [ -n "$input" ]; do
        # read the hex characters up to the first comma
        val="${input%%,*}"
        tmpinput="${input#*,}"

        if [ "$input" = "$tmpinput" ]; then
            input=""
        else
            input="$tmpinput"
        fi

        # Is this a new line? If so, print the offset
        if [ "$(("$offset" % 16))" -eq 0 ]; then
            output="${output}$(printf '%08x: ' "$offset")"
        fi

        # group values in 16-bit words, separated by spaces
        if [ "$(("$offset" % 2))" -eq 0 ]; then
            output="${output}${val}"
        else
            output="${output} ${val}"
        fi

        # Is this the end of a line?
        if [ "$(("$offset" % 16))" -eq 15 ]; then
            output="${output}
"
        fi

        offset="$(("$offset" + 1))"
    done
done

echo "$output" | xxd -r
