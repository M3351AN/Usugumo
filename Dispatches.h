#pragma once
#include "imports.h"

NTSTATUS DefaultDispatch(PDEVICE_OBJECT device_obj, PIRP irp);

NTSTATUS IoctlDispatch(PDEVICE_OBJECT device_obj, PIRP irp);