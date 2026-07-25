#pragma once

#include "../nt/functions.hpp"

namespace memview {

NTSTATUS CreateClose(PDEVICE_OBJECT device, PIRP irp);

NTSTATUS DeviceControl(PDEVICE_OBJECT device, PIRP irp);

} // namespace memview
