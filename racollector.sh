#!/bin/bash

${PREFIX}rabins -S $1 -M hard time $2 -B 20s -w - | ${PREFIX}rasplit -M time $2 -w "$3"