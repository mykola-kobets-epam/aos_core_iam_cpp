/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef GRPCHELPER_HPP_
#define GRPCHELPER_HPP_

#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>

#include <aos/common/crypto.hpp>
#include <aos/common/cryptoutils.hpp>
#include <aos/iam/certhandler.hpp>

std::shared_ptr<grpc::ServerCredentials> GetMTLSCredentials(const aos::iam::certhandler::CertInfo& certInfo,
    aos::cryptoutils::CertLoader& certLoader, aos::crypto::x509::ProviderItf& cryptoProvider);

std::shared_ptr<grpc::ServerCredentials> GetTLSCredentials(const aos::iam::certhandler::CertInfo& certInfo,
    aos::cryptoutils::CertLoader& certLoader, aos::crypto::x509::ProviderItf& cryptoProvider);

std::shared_ptr<grpc::ChannelCredentials> GetTlsChannelCredentials(const aos::iam::certhandler::CertInfo& certInfo,
    aos::cryptoutils::CertLoaderItf& certLoader, aos::crypto::x509::ProviderItf& cryptoProvider);

#endif
