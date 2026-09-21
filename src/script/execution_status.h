// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#ifndef NEURAI_SCRIPT_EXECUTION_STATUS_H
#define NEURAI_SCRIPT_EXECUTION_STATUS_H
#include "consensus/validation.h"
#include <atomic>
#include <memory>
/** Per validation attempt, shared by script workers; never global or cached. */
class ScriptExecutionStatus {
    std::atomic<bool> m_local_failure{false};
public:
    void SetLocalFailure() noexcept { m_local_failure.store(true, std::memory_order_relaxed); }
    bool HasLocalFailure() const noexcept { return m_local_failure.load(std::memory_order_relaxed); }
    bool Apply(CValidationState& state) const {
        if (!HasLocalFailure()) return true;
        // Discard any earlier rejection code/DoS score from this attempt.
        state = CValidationState();
        return state.Error("local-cryptographic-backend-failure");
    }
};
/** Declare BEFORE CCheckQueueControl, so its destructor runs AFTER workers drain.
 * A local failure takes priority even if validation returned early for another
 * reason while an already queued check was still running.
 */
class ScriptExecutionStatusGuard {
    std::shared_ptr<ScriptExecutionStatus> m_status;
    CValidationState& m_state;
public:
    ScriptExecutionStatusGuard(std::shared_ptr<ScriptExecutionStatus> status, CValidationState& state)
        : m_status(std::move(status)), m_state(state) {}
    ~ScriptExecutionStatusGuard() { m_status->Apply(m_state); }
};
#endif
