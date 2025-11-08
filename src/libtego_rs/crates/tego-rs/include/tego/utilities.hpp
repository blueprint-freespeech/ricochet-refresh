#pragma once

#define TEGO_STRINGIFY_IMPL(X) #X
#define TEGO_STRINGIFY(X) TEGO_STRINGIFY_IMPL(X)

#define TEGO_THROW_MSG(...) throw std::runtime_error(std::string("runtime error " __FILE__ ":" TEGO_STRINGIFY(__LINE__) " " __VA_OPT__(,) __VA_ARGS__));

#define TEGO_THROW_IF_FALSE(B) if (!(B)) { TEGO_THROW_MSG(TEGO_STRINGIFY(B) " must be true"); }

#define TEGO_THROW_IF_TRUE(B) if (B) { TEGO_THROW_MSG(TEGO_STRINGIFY(B) " must be false"); }
#define TEGO_THROW_IF TEGO_THROW_IF_TRUE

#define TEGO_THROW_IF_NULL(PTR) if ((PTR) == nullptr) { TEGO_THROW_MSG(TEGO_STRINGIFY(PTR) " must not be null"); }

#define TEGO_THROW_IF_NOT_NULL(PTR) if ((PTR) != nullptr) { TEGO_THROW_MSG(TEGO_STRINGIFY(PTR) " must be null") }

#define TEGO_THROW_IF_EQUAL(A, B) if((A) == (B)) { TEGO_THROW_MSG(TEGO_STRINGIFY(A) " and " TEGO_STRINGIFY(B) " must not be equal"); }

namespace tego
{
    //
    // call functor at end of scope
    //
    template<typename T>
    class scope_exit
    {
    public:
        scope_exit() = delete;
        scope_exit(const scope_exit&) = delete;
        scope_exit& operator=(const scope_exit&) = delete;
        scope_exit& operator=(scope_exit&&) =  delete;

        scope_exit(scope_exit&&) = default;
        scope_exit(T&& functor)
         : functor_(new T(std::move(functor)))
        {
            static_assert(std::is_same<void, decltype(functor())>::value);
        }

        ~scope_exit()
        {
            if (functor_.get())
            {
                functor_->operator()();
            }
        }

    private:
        std::unique_ptr<T> functor_;
    };


    template<typename FUNC>
    auto make_scope_exit(FUNC&& func) ->
        scope_exit<typename std::remove_reference<decltype(func)>::type>
    {
        return {std::move(func)};
    }

    //
    // constexpr strlen for compile-time null terminated C String constants
    //
    template<size_t N>
    constexpr size_t static_strlen(const char (&str)[N])
    {
        if (str[N-1] != 0) throw "C String missing null terminator";
        for(size_t i = 0; i < (N - 1); i++)
        {
            if (str[i] == 0) throw "C String has early null terminator";
        }
        return N-1;
    }

    //
    // helper class for populating out T** params into unique_ptr<T> objects
    //
    template<typename T>
    class out_unique_ptr
    {
    public:
        out_unique_ptr() = delete;
        out_unique_ptr(const out_unique_ptr&) = delete;
        out_unique_ptr(out_unique_ptr&&) = delete;
        out_unique_ptr& operator=(const out_unique_ptr&) = delete;
        out_unique_ptr& operator=(out_unique_ptr&&) = delete;

        out_unique_ptr(std::unique_ptr<T>& u) : u_(u) {}
        ~out_unique_ptr()
        {
            u_.reset(t_);
        }

        operator T**()
        {
            return &t_;
        }

    private:
        T* t_ = nullptr;
        std::unique_ptr<T>& u_;
    };

    //
    // helper function for populating out T** params
    // example:
    //
    // void give_int(int** outInt);
    // std::unique_ptr<int> pint;
    // give_int(tego::out(pint));
    // int val = *pint;
    //
    template<typename T>
    out_unique_ptr<T> out(std::unique_ptr<T>& ptr)
    {
        return {ptr};
    }
}
