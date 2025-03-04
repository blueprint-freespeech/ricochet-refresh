#include "error.hpp"

extern "C"
{
    const char* tego_error_get_message(const tego_error* error)
    {
        return error->message.c_str();
    }
}