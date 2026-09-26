// Copyright (c) 2026 The Neurai developers
// Distributed under the MIT software license, see COPYING.
#include "crypto/backend_error.h"
#include "script/interpreter.h"
#include "script/execution_status.h"
#include "validation.h"
#include "checkqueue.h"
#include "test/test_neurai.h"
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>
#include <thread>
#include <chrono>

bool CheckInputs(const CTransaction&, CValidationState&, const CCoinsViewCache&, bool,
                 script_verify_flags, bool, bool, PrecomputedTransactionData&,
                 std::vector<CScriptCheck>* = nullptr, std::shared_ptr<std::vector<CTxOut>> = nullptr,
                 ChainContext = {}, bool* = nullptr, std::shared_ptr<PoseidonWorkBudget> = nullptr,
                 std::shared_ptr<ScriptExecutionStatus> = nullptr);
namespace {
struct BackendChecker : BaseSignatureChecker {
    bool fail;
    explicit BackendChecker(bool f) : fail(f) {}
    bool CheckSig(const std::vector<unsigned char>&, const std::vector<unsigned char>&,
                  const CScript&, SigVersion, uint8_t) const override {
        if (fail) throw CryptoBackendError();
        return true;
    }
};
CTransaction Transaction() {
    CMutableTransaction tx;
    tx.vin.resize(1);tx.vout.emplace_back(0,CScript()<<OP_TRUE);
    tx.vin[0].prevout=COutPoint(uint256S("01"),0);
    tx.vin[0].scriptSig=CScript()<<std::vector<unsigned char>{1}<<std::vector<unsigned char>{2};
    return CTransaction(tx);
}
struct QueuedCheck {
    CScriptCheck check;
    const BackendChecker* checker{nullptr};
    std::atomic<bool>* completed{nullptr};
    std::atomic<bool>* gate{nullptr};
    bool operator()() {
        while (!gate->load()) std::this_thread::yield();
        const bool ok = check.CheckWith(*checker);
        completed->store(true);
        return ok;
    }
    void swap(QueuedCheck& other) {
        check.swap(other.check); std::swap(checker,other.checker);
        std::swap(completed,other.completed);
        std::swap(gate,other.gate);
    }
};
}
BOOST_FIXTURE_TEST_SUITE(backend_failure_tests, BasicTestingSetup)
BOOST_AUTO_TEST_CASE(typed_error_survives_interpreter) {
    BackendChecker checker(true);
    std::vector<std::vector<unsigned char>> stack{{1},{2}};
    ScriptError error=SCRIPT_ERR_OK;
    BOOST_CHECK(!EvalScript(stack,CScript()<<OP_CHECKSIG,{},checker,SIGVERSION_AUTHSCRIPT,&error));
    BOOST_CHECK(error==SCRIPT_ERR_BACKEND_FAILURE);
}
BOOST_AUTO_TEST_CASE(synchronous_error_and_recovery) {
    const auto tx=Transaction();PrecomputedTransactionData data(tx);
    auto status=std::make_shared<ScriptExecutionStatus>();
    CScriptCheck check(CTxOut(0,CScript()<<OP_CHECKSIG),tx,0,{},false,&data,nullptr,nullptr,{},nullptr,status);
    BOOST_CHECK(!check.CheckWith(BackendChecker(true)));
    BOOST_CHECK(check.GetScriptError()==SCRIPT_ERR_BACKEND_FAILURE);
    CValidationState state;
    BOOST_CHECK(!status->Apply(state));
    BOOST_CHECK(state.IsError());
    int score=0;BOOST_CHECK(!state.IsInvalid(score));BOOST_CHECK_EQUAL(score,0);
    auto recovered=std::make_shared<ScriptExecutionStatus>();
    CScriptCheck retry(CTxOut(0,CScript()<<OP_CHECKSIG),tx,0,{},false,&data,nullptr,nullptr,{},nullptr,recovered);
    BOOST_CHECK(retry.CheckWith(BackendChecker(false)));
    CValidationState fresh;BOOST_CHECK(recovered->Apply(fresh));BOOST_CHECK(fresh.IsValid());
}
BOOST_AUTO_TEST_CASE(checkinputs_local_state_not_cached_or_invalid) {
    LOCK(cs_main);
    const auto tx=Transaction(); PrecomputedTransactionData data(tx);
    CCoinsView base; CCoinsViewCache coins(&base);
    coins.AddCoin(tx.vin[0].prevout,Coin(CTxOut(0,CScript()<<OP_TRUE),1,false),false);
    auto failed=std::make_shared<ScriptExecutionStatus>();failed->SetLocalFailure();
    CValidationState state;
    BOOST_CHECK(!CheckInputs(tx,state,coins,true,{},true,true,data,nullptr,nullptr,{},nullptr,nullptr,failed));
    BOOST_CHECK(state.IsError());BOOST_CHECK(!state.IsInvalid());
    CValidationState retry;
    BOOST_CHECK(CheckInputs(tx,retry,coins,true,{},true,true,data));
    BOOST_CHECK(retry.IsValid());
    CValidationState hot;
    BOOST_CHECK(!CheckInputs(tx,hot,coins,true,{},true,true,data,nullptr,nullptr,{},nullptr,nullptr,failed));
    BOOST_CHECK(hot.IsError());
    CMutableTransaction bad(tx);
    bad.vin[0].prevout=COutPoint(uint256S("02"),0);
    const CTransaction invalid(bad); PrecomputedTransactionData invalidData(invalid);
    coins.AddCoin(invalid.vin[0].prevout,Coin(CTxOut(0,CScript()<<OP_FALSE),1,false),false);
    CValidationState failedInvalid;
    BOOST_CHECK(!CheckInputs(invalid,failedInvalid,coins,true,{},true,true,invalidData,nullptr,nullptr,{},nullptr,nullptr,failed));
    BOOST_CHECK(failedInvalid.IsError());
    CValidationState retryInvalid;
    BOOST_CHECK(!CheckInputs(invalid,retryInvalid,coins,true,{},true,true,invalidData));
    BOOST_CHECK(retryInvalid.IsInvalid()); // the local failure did not seed a positive cache entry
}
BOOST_AUTO_TEST_CASE(queue_error_and_early_return_priority) {
    const auto tx=Transaction();PrecomputedTransactionData data(tx);
    BackendChecker checker(true);
    for (bool early : {false,true}) {
        CCheckQueue<QueuedCheck> queue(1);
        boost::thread_group threads;
        threads.create_thread([&] { queue.Thread(); });
        auto status=std::make_shared<ScriptExecutionStatus>();
        CValidationState state;
        std::atomic<bool> completed{false};
        std::atomic<bool> gate{!early};
        {
            ScriptExecutionStatusGuard guard(status,state);
            CCheckQueueControl<QueuedCheck> control(&queue);
            std::vector<QueuedCheck> jobs(1);
            jobs[0].check=CScriptCheck(CTxOut(0,CScript()<<OP_CHECKSIG),tx,0,{},false,&data,nullptr,nullptr,{},nullptr,status);
            jobs[0].checker=&checker;
            jobs[0].completed=&completed;
            jobs[0].gate=&gate;
            control.Add(jobs);
            if (early) {
                // The local failure cannot occur until after the unrelated rejection.
                state.Invalid(false,REJECT_INVALID,"unrelated-earlier-rejection");
                gate.store(true);
                // No explicit Wait: the queue controller must drain before the guard.
            } else {
                // Master has not entered Wait: completion proves worker execution.
                for (unsigned i=0; i<1000 && !completed.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                BOOST_CHECK(completed.load());
                BOOST_CHECK(!control.Wait()); BOOST_CHECK(!status->Apply(state));
            }
        }
        threads.interrupt_all();threads.join_all();
        BOOST_CHECK(status->HasLocalFailure());BOOST_CHECK(state.IsError());
        BOOST_CHECK(!state.IsInvalid());
        BOOST_CHECK_EQUAL(state.GetRejectCode(), 0U);
        BOOST_CHECK_EQUAL(state.GetRejectReason(), "local-cryptographic-backend-failure");
    }
}
BOOST_AUTO_TEST_CASE(consensus_failure_stays_invalid) {
    const auto tx=Transaction();PrecomputedTransactionData data(tx);
    auto status=std::make_shared<ScriptExecutionStatus>();
    CScriptCheck check(CTxOut(0,CScript()<<OP_FALSE),tx,0,{},false,&data,nullptr,nullptr,{},nullptr,status);
    BOOST_CHECK(!check());BOOST_CHECK(!status->HasLocalFailure());
    CValidationState state;state.Invalid(false,REJECT_INVALID,"script-failed");
    BOOST_CHECK(status->Apply(state));BOOST_CHECK(state.IsInvalid());
}
BOOST_AUTO_TEST_SUITE_END()
