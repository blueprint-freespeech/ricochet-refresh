#pragma once

// todo: remove me once we integrate the real backend
namespace mock {
typedef void* ContactHandle;

wxString nickname_from_contact_handle(const ContactHandle contact_handle);
wxBitmap avatar_from_contact_handle(const ContactHandle contact_handle);
} // namespace mock
