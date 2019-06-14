#!/bin/bash

if [ ! -z "${DEPS_PACKAGES}" ]; then

    function scrape_packages_ubuntu_com() {
        local package_name=$1;shift
        local distroseries_name=$1;shift
        local arch_name=$1;shift
        local distro_name="ubuntu"

        local url="https://packages.ubuntu.com/${distroseries_name}/${arch_name}/${package_name}/download"
        curl -s "$url" | \
            perl -ne '@links= $_ =~ /href\s*=\s*"?([^"\s>]+)/gis; @links=grep(/ubuntu\/pool\//, @links); @links=grep(/\.ubuntu\.com\//, @links); print "$links[0]\n";' | \
            grep -m 1 ubuntu | sed 's/http.*archive\.ubuntu\.com/http:\/\/archive.ubuntu.com/'
    }

    function get_package_url() {
        local package_name=$1;shift
        local distroseries_name=$1;shift || :
        local arch_name=$1;shift || :
        local distro_name=$1;shift || :

        : ${distro_name:=ubuntu}
        : ${distroseries_name:=bionic}
        : ${arch_name:=amd64}

        if [ "${distro_name}" = "ubuntu" ]; then
            scrape_packages_ubuntu_com "$package_name" "$distroseries_name" "$arch_name"
        else
            echo "Unsupported Distro" >&2
            false
        fi
    }

    : ${DRELEASE_NAME:="bionic"}; export DRELEASE_NAME;
    : ${DARCH_NAME:="amd64"}; export DARCH_NAME;
    : ${DISTRO_NAME:="ubuntu"}; export DISTRO_NAME;

    : ${DEPS_PACKAGES_URLS:=""};

    for p in ${DEPS_PACKAGES}; do
        u="$(get_package_url "$p" "${DRELEASE_NAME}" "${DARCH_NAME}" "${DISTRO_NAME}")"
        DEPS_PACKAGES_URLS="${DEPS_PACKAGES_URLS} ${u}"
    done
fi

if [ ! -z "${DEPS_PACKAGES_URLS}" ]; then
    export DEPS_PACKAGES_URLS
    export DPACKAGES_HASH=$(echo -n "${DEPS_PACKAGES_URLS}"|md5sum|cut -d" " -f1)
    export DPACKAGES_PREFIX="$HOME/cache/prefix/${DPACKAGES_HASH}"
fi


