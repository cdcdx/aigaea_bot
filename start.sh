#!/bin/bash
if [ ${#VIRTUAL_ENV} -gt 0 ]; then
    deactivate
fi

if [ "$1" == "init" ]; then
    if [ -d ".venv" ]; then
        echo Virtual Environment already exists
        source .venv/bin/activate
        pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    else
        echo Install Virtual Environment...
        python3 -m venv .venv
        source .venv/bin/activate
        pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    fi
elif [ "$1" == "clear" ]; then
    rm -fr "__pycache__"
    rm -fr "src/__pycache__"
    rm -fr "utils/__pycache__"
    echo "" > "data/logs/logging.log"
else
    echo Virtual Environment Activation...
    source .venv/bin/activate

    echo Launching the app...
    python3 main.py $1 $2 $3 $4 $5 $6 $7 $8 $9
fi
