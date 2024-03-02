#include "VirtualTerminalSupport.hpp"

#ifdef _WIN32

#include <optional>
#include <windows.h>

class VirtualTerminalSupport::Impl
{
public:
    Impl()
    : hStdOut{GetStdHandle(STD_OUTPUT_HANDLE)}
    , originalMode{[this]
                   {
                       auto mode = DWORD{};
                       return GetConsoleMode(hStdOut, &mode) ? std::optional{mode} : std::nullopt;
                   }()}
    {
        if (originalMode)
            SetConsoleMode(hStdOut, *originalMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    ~Impl()
    {
        if (originalMode)
            SetConsoleMode(hStdOut, *originalMode);
    }

private:
    const HANDLE               hStdOut;
    const std::optional<DWORD> originalMode;
};

#else

class VirtualTerminalSupport::Impl
{
};

#endif // _WIN32

VirtualTerminalSupport::VirtualTerminalSupport()
: m_impl{std::make_unique<Impl>()}
{
}

VirtualTerminalSupport::~VirtualTerminalSupport() = default;
