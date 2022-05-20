# SPDX-FileCopyrightText: 2022 Blueprint for Free Speech <ricochet@blueprintforfreespeech.net>
#
# SPDX-License-Identifier: GPL-3.0-only

function (mingw_setup_static_build target)
    target_link_options(${target} PRIVATE "-static")
endfunction ()