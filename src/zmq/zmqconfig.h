// Copyright (c) 2014 The Bitcoin Core developers
// Copyright (c) 2017-2019 The Neurai Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEURAI_ZMQ_ZMQCONFIG_H
#define NEURAI_ZMQ_ZMQCONFIG_H

#if defined(HAVE_CONFIG_H)
#include "config/neurai-config.h"
#endif

#include <stdarg.h>
#include <string>

#if ENABLE_ZMQ
#include <zmq.h>
#endif

#include "primitives/block.h"
#include "primitives/transaction.h"

void zmqError(const char *str);

#endif // NEURAI_ZMQ_ZMQCONFIG_H
