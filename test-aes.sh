#!/bin/bash
for i in {1..2}; do rm *.db3; build-out/sqlite3shell test$i.db3 ".read test/test$i.sql"; echo "-------------------------"; done
