#pragma once

#include <ntifs.h>

namespace memview {

class ProcessRef
{
public:
    explicit ProcessRef(HANDLE pid)
    {
        m_status = PsLookupProcessByProcessId(pid, &m_process);
    }

    ~ProcessRef()
    {
        if (m_process)
            ObDereferenceObject(m_process);
    }

    ProcessRef(const ProcessRef&)            = delete;
    ProcessRef& operator=(const ProcessRef&) = delete;

    NTSTATUS status() const { return m_status; }
    PEPROCESS get() const   { return m_process; }

private:
    PEPROCESS m_process = nullptr;
    NTSTATUS  m_status  = STATUS_UNSUCCESSFUL;
};

class ProcessAttach
{
public:
    explicit ProcessAttach(PEPROCESS process)
    {
        KeStackAttachProcess(process, &m_apc);
    }

    ~ProcessAttach()
    {
        KeUnstackDetachProcess(&m_apc);
    }

    ProcessAttach(const ProcessAttach&)            = delete;
    ProcessAttach& operator=(const ProcessAttach&) = delete;

private:
    KAPC_STATE m_apc;
};

} // namespace memview
