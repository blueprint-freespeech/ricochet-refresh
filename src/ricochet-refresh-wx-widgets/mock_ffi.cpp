#include "mock_ffi.hpp"

#include "ui/metrics.hpp"

namespace mock {
wxString nickname_from_contact_handle(const ContactHandle contact_handle) {
    constexpr size_t NICKNAME_COUNT = 8;
    const static wxString nicknames[NICKNAME_COUNT] = {
        "Alice",
        "Bridgette",
        "Claire",
        "Danielle",
        "Elizabeth",
        "Felicia",
        "Gabriella",
        "Harriet",
    };
    return nicknames[reinterpret_cast<uintptr_t>(contact_handle) % NICKNAME_COUNT];
}

wxBitmap avatar_from_contact_handle(const ContactHandle contact_handle) {
    // todo: load actual avatars
    const static wxBitmap debug_avatar = []() {
        constexpr unsigned char avatar_data[] = {0xFF, 0xAA, 0xFF};
        const auto avatar_size = Metrics::AVATAR_SIZE;
        auto avatar_image = wxImage(1, 1, const_cast<unsigned char*>(avatar_data), true);
        avatar_image.Rescale(avatar_size, avatar_size, wxIMAGE_QUALITY_BILINEAR);
        return wxBitmap(avatar_image);
    }();
    return debug_avatar;
}
} // namespace mock