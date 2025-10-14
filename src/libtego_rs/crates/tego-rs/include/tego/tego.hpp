#pragma once
// C

// libtego
#include <tego/tego.h>

// C++

// standard library
#include <stdexcept>
#include <memory>
#include <utility>
#include <memory>
#include <type_traits>

// libtego
#include <tego/utilities.hpp>
//#define ENABLE_TEGO_LOGGER
#include <tego/logger.hpp>

namespace tego
{
    //
    // converts tego_error** C style error handling to exceptions
    //
    class throw_on_error
    {
    public:
        ~throw_on_error() noexcept(false)
        {
            if (error_ != nullptr)
            {
                logger::println("exception thrown : {}", tego_error_get_message(error_));
                std::runtime_error ex(tego_error_get_message(error_));
                tego_error_delete(error_);
                error_ = nullptr;
                throw ex;
            }
        }

        operator tego_error**()
        {
            return &error_;
        }
    private:
        tego_error* error_ = nullptr;
    };
}


// define deleters for using unique_ptr and shared_ptr with tego types

#define TEGO_DEFAULT_DELETE_IMPL(TYPE)\
namespace std {\
    template<> class default_delete<TYPE> {\
    public:\
        void operator()(TYPE* val) { TYPE##_delete(val); }\
    };\
}

TEGO_DEFAULT_DELETE_IMPL(tego_ed25519_private_key)
TEGO_DEFAULT_DELETE_IMPL(tego_v3_onion_service_id)
TEGO_DEFAULT_DELETE_IMPL(tego_tor_launch_config)
TEGO_DEFAULT_DELETE_IMPL(tego_tor_daemon_config)
TEGO_DEFAULT_DELETE_IMPL(tego_pluggable_transport_config)
TEGO_DEFAULT_DELETE_IMPL(tego_user_id)
