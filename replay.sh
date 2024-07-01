OUTPUT_DIR=$(readlink -f ./output_dir)/default/crashes
PYTHON_PATH=$(readlink -f ./cpython/python)
NUM_CRASHES=1

if [ "$1" != "" ]; then
    NUM_CRASHES=$1
    if [ $NUM_CRASHES -le 0 ]; then
        echo "crashed number $1"
        exit
    fi
fi

CRASH_FILE=$(ls $OUTPUT_DIR | head -n $NUM_CRASHES | tail -n 1)
echo "replay" $OUTPUT_DIR/$CRASH_FILE
cat $OUTPUT_DIR/$CRASH_FILE | $PYTHON_PATH
