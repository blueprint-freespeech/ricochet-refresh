function (mingw_setup_static_build target)
    target_link_options(${target} "-static")
endfunction ()