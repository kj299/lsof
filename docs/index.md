# lsof (LiSt Open Files)

**lsof** is a command for `LiSting Open Files`. You can use lsof for example to:

- Find uses of a specific open file: `lsof /path/to/file`
- Find an unlinked open file: `lsof +L1`
- Find processes blocking umount: `lsof /mnt`
- Find tcp/udp sockets: `lsof -i`
- Find files open to a process with known PID: `lsof -p 1234`
- Find files open to a named command: `lsof -c bash`
- Find files open by a specific user: `lsof -u somebody`

## History

lsof was originally developed and maintained by Vic Abell since 1994. The [lsof-org team at GitHub](https://github.com/lsof-org/lsof) takes over the maintainership of lsof. You can find the latest release at [GitHub Release](https://github.com/lsof-org/lsof/releases).

## OS Support

Actively maintained and supported:

- Linux
- FreeBSD
- Darwin(macOS)
- NetBSD
- OpenBSD
- Solaris/OpenIndiana

Not maintained for lack of maintainers but pull requests are welcome:

- IBM AIX

(Upstream also lists HP-UX, SCO OpenServer and UnixWare here. Their sources were
removed from this repository in PR #81, since nothing here builds them.)

In this repository, `.github/workflows/build.yml` builds and tests lsof on
Ubuntu 22.04, Ubuntu 24.04 and macOS. `.cirrus.yml` (FreeBSD) and `.builds/`
(NetBSD, OpenBSD) are configured as well; whether those services run depends on
the Cirrus and sourcehut set-up of the repository that hosts them. (Upstream's
list here — Alpine, Arch, CentOS, Debian, Fedora, NixOS, openSUSE and older
Ubuntu — came from a CircleCI configuration this repository no longer has.)

Additionally, lsof is tested by maintainers manually on the following platforms:

- Solaris 11
- OpenIndiana 5

lsof is provided by package manager in the following repositories:

<a href="https://repology.org/project/lsof/versions">
    <img src="https://repology.org/badge/vertical-allrepos/lsof.svg" alt="Packaging status">
</a>