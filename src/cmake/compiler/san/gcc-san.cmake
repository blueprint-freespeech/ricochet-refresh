# SPDX-FileCopyrightText: 2022 Blueprint for Free Speech <ricochet@blueprintforfreespeech.net>
#
# SPDX-License-Identifier: GPL-3.0-only

# the only sanitizer that clang supports that GCC doesn't is memorysan, which we don't support anyway
include(clang-san)

function (gcc_setup_sanitizers target)
    clang_setup_sanitizers(${target})
endfunction ()
