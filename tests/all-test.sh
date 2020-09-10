#!/bin/bash

# test if  already in tests subdirectory
# if not, then go  to tests subdirectory in this shell session
echo "TEST_DIR: $TEST_DIR"
PN="$(basename "$0")"
CURDIR=${PWD}
THISDIR="$(pwd -P)"
THIS_DIRNAME="$(dirname $CURDIR)"
SCRIPTREALPATH="$(realpath "$0")"
SCRIPTFULLPATH="$(readlink -e "$SCRIPTREALPATH")"
SCRIPTPATH="$(dirname $SCRIPTFULLPATH)"
TEST_DIR=$SCRIPTPATH
TEST_DIRNAME=$(basename "$TEST_DIR")
if [ "$THIS_DIRNAME" == "$TEST_DIRNAME" ]; then
  THIS_DIRNAME="../"
fi

echo "CURDIR, where current directory is at: $CURDIR"
echo "THISDIR, where execution is at: $THISDIR"
echo "SCRIPTREALPATH, where script is : $SCRIPTREALPATH"
echo "SCRIPTFULLPATH, where script is : $SCRIPTFULLPATH"
echo "SCRIPTPATH, where script is : $SCRIPTPATH"
echo "TEST_DIR, where full-path test directory is : $TEST_DIR"
echo "TEST_DIRNAME, where test directory is : $TEST_DIRNAME"
echo "THIS_DIRNAME, the project dir to include this module for testing: $THIS_DIRNAME"

cd "$THIS_DIRNAME"
LIST_TESTS="$(ls $TEST_DIR/test_*.py)"
FAILED_MODULES=''
ERR_COUNT=0
echo "LIST_TESTS: $LIST_TESTS"

for THIS_TEST in $LIST_TESTS; do
    ALT_THIS_TEST=$(basename $THIS_TEST)
    THIS_TEST=$(echo "$ALT_THIS_TEST" | cut -f 1 -d '.')
    python3 -m unittest "${TEST_DIRNAME}"."${THIS_TEST}"
    RETSTS=$?
    if [ $RETSTS -ne 0 ]; then
    ((ERR_COUNT++))
    FAILED_MODULES="$FAILED_MODULES, $THIS_TEST"
    fi
done
echo "ERR_COUNT: $ERR_COUNT"
echo "FAILED_MODULES: $FAILED_MODULES"
