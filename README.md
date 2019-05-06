
mkrpm
=====

This is a tool to create a RPM of a file or directory, without the use of spec files,
rpmbuild, or librpm.

Why
---

Making a RPM is hard. The tool provided by rpm, `rpmbuild`, only supports the
use case of building a package from source. The instructions to build this
package must be described in a spec file, a text file format only used by RPM
that is difficult to learn and more than a little clunky to parse. Attempting
to use librpm directly in a custom program has its own pitfalls, since it is
written only with installing, upgrading, or removing a package in mind: it
requires a system with the RPM configuration and database files available, and
often requires a transaction object whether you are going to perform a
transaction or not.

It doesn't have to be like this. Sometimes you just want to package up some
files in a RPM.
