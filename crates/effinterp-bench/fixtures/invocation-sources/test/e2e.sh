SRC=$(cd $(dirname "$0"); pwd)
source "${SRC}/e2e/include.sh"
runTest ./x.sh
