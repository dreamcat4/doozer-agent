
prepdist() {

    rm -rf ubuntu/$1-$2

    debootstrap --arch=$2 $1 ubuntu/$1-$2 http://se.archive.ubuntu.com/ubuntu/
    cp ../nosync/nosync$3.so ubuntu/$1-$2/lib/
    echo >ubuntu/$1-$2/etc/ld.so.preload /lib/nosync$3.so

    echo  >ubuntu/$1-$2/etc/apt/sources.list "deb mirror://mirrors.ubuntu.com/mirrors.txt $1 main restricted universe multiverse"
    echo >>ubuntu/$1-$2/etc/apt/sources.list "deb mirror://mirrors.ubuntu.com/mirrors.txt $1-updates main restricted universe multiverse"
    echo >>ubuntu/$1-$2/etc/apt/sources.list "deb mirror://mirrors.ubuntu.com/mirrors.txt $1-backports main restricted universe multiverse"
    echo >>ubuntu/$1-$2/etc/apt/sources.list "deb mirror://mirrors.ubuntu.com/mirrors.txt $1-security main restricted universe multiverse"

    cat ubuntu/$1-$2/etc/apt/sources.list

    chroot ubuntu/$1-$2 apt-get update

    rm -rf ubuntu/$1-$2/var/cache/apt/archives/*.deb
    (cd ubuntu/$1-$2 && tar cf ../$1-$2.tar *)
    xz -9 <ubuntu/$1-$2.tar >ubuntu/$1-$2.tar.xz
}

set -e
set -x

mkdir -p ubuntu

prepdist precise amd64 64
prepdist precise i386 32
prepdist trusty amd64 64
prepdist trusty i386 32


