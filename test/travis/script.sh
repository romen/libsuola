set -e
DN="$(dirname "$0")"
D="$(readlink -f "$DN")"
. "$D/install_deps.sh"
. "$D/build_libsuola.sh"
. "$D/test_libsuola_unit.sh"
. "$D/test_libsuola_integration.sh"
