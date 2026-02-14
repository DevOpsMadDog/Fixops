#!/bin/bash
cd /Users/devops.ai/developement/fixops/Fixops

echo "=== FILE COUNT ==="
find suite-ui/aldeci/src -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | wc -l

echo ""
echo "=== TOTAL LINES ==="
find suite-ui/aldeci/src -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | xargs wc -l 2>/dev/null | tail -1

echo ""
echo "=== BY DIRECTORY ==="
for dir in components pages lib stores layouts; do
    count=$(find "suite-ui/aldeci/src/$dir" -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | wc -l)
    lines=$(find "suite-ui/aldeci/src/$dir" -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | xargs wc -l 2>/dev/null | tail -1)
    echo "  $dir: $count files, $lines"
done

echo ""
echo "=== CHECKING V3-CLAIMED DIRS ==="
for dir in hooks store types utils; do
    if [ -d "suite-ui/aldeci/src/$dir" ]; then
        echo "  $dir: EXISTS"
    else
        echo "  $dir: DOES NOT EXIST"
    fi
done

echo ""
echo "=== COMPONENT FILES ==="
find suite-ui/aldeci/src/components -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | sort

echo ""
echo "=== PAGE FILES ==="
find suite-ui/aldeci/src/pages -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | sort

echo ""
echo "=== LIB FILES ==="
find suite-ui/aldeci/src/lib -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | sort

echo ""
echo "=== STORE FILES ==="
find suite-ui/aldeci/src/stores -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | sort

echo ""
echo "=== PER-FILE LINE COUNTS ==="
find suite-ui/aldeci/src -type f \( -name "*.tsx" -o -name "*.ts" \) 2>/dev/null | grep -v node_modules | sort | xargs wc -l 2>/dev/null

echo ""
echo "=== DONE ==="

