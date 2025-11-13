#!/bin/bash

sphinx-apidoc -o docs/rst oidFed
cd docs
make clean
make html