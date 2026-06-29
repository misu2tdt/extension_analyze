#!/bin/bash
# Submit 5 jobs cùng lúc
for i in {1..5}; do
    curl -X POST http://localhost:8000/jobs/analyze &
done
wait
echo ""
echo "All submitted."