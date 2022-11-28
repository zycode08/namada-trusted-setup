#!/bin/bash

while :
do
  wget -O Namada.json https://www.reddit.com/r/Namada.json
  tokens=$(cat Namada.json | jq '.data.children | .[].data | select(.title | test("Cohort 9")) | .selftext' | tr ' ' '\n' | grep -o "^9nFe[^\\\\|^\"]*")

  if [[ -z "$tokens" ]]; then
    echo "empty"
    sleep 60
    continue
  else
    COUNTER=1
    for token in $tokens;do
      echo "token $COUNTER: $token"
      nohup namada-ts contribute default https://contribute.namada.net $token &> log_${COUNTER}.txt &
      COUNTER=$[$COUNTER +1]
    done

    break
  fi
done
