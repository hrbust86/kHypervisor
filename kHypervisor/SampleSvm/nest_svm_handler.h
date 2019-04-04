#pragma once

struct GuestContext;

VOID SvmVmxonEmulate(_In_ GuestContext* guest_context);

VOID SvmVmsaveEmulate(_In_ GuestContext* guest_context);