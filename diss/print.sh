#!/bin/bash

echo ""
echo "SPELLING ERRORS:"
aspell -t list --home-dir=. --personal=dict.aspell.lang.pws <diss.tex #print spelling errors
echo ""
echo "WORD COUNT:"
texcount diss.tex | sed -n 3p