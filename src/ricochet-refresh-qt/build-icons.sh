#!/usr/bin/bash

set -x
set -e

SOURCE=ricochet-refresh.svg

# build icons/ricochet_refresh.png
inkscape ${SOURCE} -w 1024 -h 1024 -o icons/ricochet_refresh.png

# build resources/darwin/ricochet_refresh.icns
PNGS=""
for size in 16 32 128 256 512 1024
do
    OUT="ricochet-refresh.${size}x${size}.png"
    inkscape ${SOURCE} -w ${size} -h ${size} -o ${OUT}
    PNGS="${PNGS} ${OUT}"
done
png2icns resources/darwin/ricochet_refresh.icns ${PNGS}
rm ${PNGS}

# build resources/linux/icons/*
inkscape ${SOURCE} -w 48 -h 48 -o resources/linux/icons/48x48/ricochet-refresh.png
cp ${SOURCE} resources/linux/icons/scalable/ricochet-refresh.svg

# build resources/windows/ricochet_refresh.ico
PNGS=""
for size in 16 32 48 256
do
    OUT="ricochet-refresh.${size}x${size}.png"
    inkscape ${SOURCE} -w ${size} -h ${size} -o ${OUT}
    PNGS="${PNGS} ${OUT}"
done
convert ${PNGS} resources/windows/ricochet_refresh.ico
rm ${PNGS}

