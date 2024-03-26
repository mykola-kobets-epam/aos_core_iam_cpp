/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "iam/client/iamclient.hpp"
#include "iam/server/iamserver.hpp"

#include <gmock/gmock.h>

#include <test/utils/log.hpp>
#include <test/utils/softhsmenv.hpp>

#include <aos/common/crypto/mbedtls/cryptoprovider.hpp>
#include <aos/iam/certhandler.hpp>
#include <aos/iam/certmodules/pkcs11/pkcs11.hpp>

#include "mocks/identhandlermock.hpp"
#include "mocks/permissionhandlermock.hpp"
#include "mocks/remoteiamhandlermock.hpp"
#include "storagestub.hpp"

using namespace testing;
using namespace aos;
using namespace aos::iam;
using namespace aos::iam::certhandler;

/***********************************************************************************************************************
 * Suite
 **********************************************************************************************************************/

class IAMTest : public Test {
protected:
    void SetUp() override;
    void TearDown() override;

    // Default parameters
    static constexpr auto cPIN             = "admin";
    static constexpr auto cLabel           = "iam-server-test-slot";
    static constexpr auto cMaxModulesCount = 3;

    // CertHandler function
    certhandler::ModuleConfig GetCertModuleConfig(crypto::KeyType keyType);
    PKCS11ModuleConfig        GetPKCS11ModuleConfig();
    void RegisterPKCS11Module(const String& name, crypto::KeyType keyType = crypto::KeyTypeEnum::eRSA);
    void ApplyCertificate(const String& certType, uint64_t serial, CertInfo& certInfo);

    Config GetServerConfig();
    Config GetClientConfig();
    // Service providers
    crypto::MbedTLSCryptoProvider mCryptoProvider;
    test::SoftHSMEnv              mSOFTHSMEnv;
    cryptoutils::CertLoader       mCertLoader;

    // CertHandler & certmodules
    StaticArray<PKCS11Module, cMaxModulesCount> mPKCS11Modules;
    StaticArray<CertModule, cMaxModulesCount>   mCertModules;
    std::shared_ptr<CertHandler>                mCertHandler;

    // mocks
    StorageStub                    mStorage;
    identhandler::IdentHandlerMock mIdentHandler;
    permhandler::PermHandlerMock   mPermHandler;
    RemoteIAMHandlerMock           mRemoteIAMHandler;
};

void IAMTest::SetUp()
{
    InitLogs();

    mCertHandler = std::make_shared<CertHandler>();
    ASSERT_TRUE(mCryptoProvider.Init().IsNone());
    ASSERT_TRUE(mSOFTHSMEnv
                    .Init("", "certhanler-integr-tests", SOFTHSM_BASE_DIR "/softhsm2.conf", SOFTHSM_BASE_DIR "/tokens",
                        SOFTHSM2_LIB)
                    .IsNone());
    ASSERT_TRUE(mCertLoader.Init(mCryptoProvider, mSOFTHSMEnv.GetManager()).IsNone());
}

void IAMTest::TearDown()
{
    FS::ClearDir(SOFTHSM_BASE_DIR "/tokens");
}

void IAMTest::RegisterPKCS11Module(const String& name, crypto::KeyType keyType)
{
    ASSERT_TRUE(mPKCS11Modules.EmplaceBack().IsNone());
    ASSERT_TRUE(mCertModules.EmplaceBack().IsNone());
    auto& pkcs11Module = mPKCS11Modules.Back().mValue;
    auto& certModule   = mCertModules.Back().mValue;
    ASSERT_TRUE(pkcs11Module.Init(name, GetPKCS11ModuleConfig(), mSOFTHSMEnv.GetManager(), mCryptoProvider).IsNone());
    ASSERT_TRUE(certModule.Init(name, GetCertModuleConfig(keyType), mCryptoProvider, pkcs11Module, mStorage).IsNone());
    ASSERT_TRUE(mCertHandler->RegisterModule(certModule).IsNone());
}

Config IAMTest::GetServerConfig()
{
    Config config;

    config.mCertStorage               = "server";
    config.mIAMPublicServerURL        = "localhost:8088";
    config.mIAMProtectedServerURL     = "localhost:8089";
    config.mNodeID                    = "node0";
    config.mNodeType                  = "iam-node-type";
    config.mFinishProvisioningCmdArgs = config.mDiskEncryptionCmdArgs = {};

    return config;
}

Config IAMTest::GetClientConfig()
{
    Config config;

    config.mCertStorage               = "server";
    config.mIAMPublicServerURL        = "localhost:8088";
    config.mIAMProtectedServerURL     = "localhost:8089";
    config.mNodeID                    = "iam-node-id";
    config.mNodeType                  = "iam-node-type";
    config.mFinishProvisioningCmdArgs = config.mDiskEncryptionCmdArgs = {};
    config.mRemoteIAMs = {RemoteIAM {"node0", "127.0.0.1:8089", std::chrono::seconds(10)}};

    return config;
}

certhandler::ModuleConfig IAMTest::GetCertModuleConfig(crypto::KeyType keyType)
{
    certhandler::ModuleConfig config;
    config.mKeyType         = keyType;
    config.mMaxCertificates = 2;
    config.mExtendedKeyUsage.EmplaceBack(ExtendedKeyUsageEnum::eClientAuth);
    config.mAlternativeNames.EmplaceBack("epam.com");
    config.mAlternativeNames.EmplaceBack("www.epam.com");
    config.mSkipValidation = false;
    return config;
}

PKCS11ModuleConfig IAMTest::GetPKCS11ModuleConfig()
{
    PKCS11ModuleConfig config;
    config.mLibrary         = SOFTHSM2_LIB;
    config.mSlotID          = mSOFTHSMEnv.GetSlotID();
    config.mUserPINPath     = CERTIFICATES_DIR "/pin.txt";
    config.mModulePathInURL = true;
    return config;
}

void IAMTest::ApplyCertificate(const String& certType, uint64_t serial, CertInfo& certInfo)
{
    StaticString<crypto::cCSRPEMLen> csr;
    ASSERT_TRUE(mCertHandler->CreateKey(certType, "Aos Core", cPIN, csr).IsNone());

    // create certificate from CSR, CA priv key, CA cert
    StaticString<crypto::cPrivKeyPEMLen> caKey;
    ASSERT_TRUE(FS::ReadFileToString(CERTIFICATES_DIR "/ca.key", caKey).IsNone());

    StaticString<crypto::cCertPEMLen> caCert;
    ASSERT_TRUE(FS::ReadFileToString(CERTIFICATES_DIR "/ca.pem", caCert).IsNone());

    auto                              serialArr = Array<uint8_t>(reinterpret_cast<uint8_t*>(&serial), sizeof(serial));
    StaticString<crypto::cCertPEMLen> clientCertChain;

    ASSERT_TRUE(mCryptoProvider.CreateClientCert(csr, caKey, caCert, serialArr, clientCertChain).IsNone());

    // add CA cert to the chain
    clientCertChain.Append(caCert);

    // apply client certificate
    // FS::WriteStringToFile(CERTIFICATES_DIR "/client-out.pem", clientCertChain, 0666);
    ASSERT_TRUE(mCertHandler->ApplyCertificate(certType, clientCertChain, certInfo).IsNone());
    EXPECT_EQ(certInfo.mSerial, serialArr);
}

/***********************************************************************************************************************
 * Static
 **********************************************************************************************************************/

TEST_F(IAMTest, DISABLED_GetVersion)
{
    CertInfo clientInfo, serverInfo;

    RegisterPKCS11Module("client");
    ASSERT_TRUE(mCertHandler->SetOwner("client", cPIN).IsNone());

    RegisterPKCS11Module("server");

    ApplyCertificate("client", 0x3333444, clientInfo);
    ApplyCertificate("server", 0x3333333, serverInfo);

    IAMServer server;
    server.Init(GetServerConfig(), mCertHandler.get(), &mIdentHandler, &mPermHandler, &mRemoteIAMHandler, mCertLoader,
        mCryptoProvider, false);
    LOG_INF() << "Server initialized";

    ::iam::RemoteIAMClient client;
    ASSERT_TRUE(client.Init(GetClientConfig(), *mCertHandler, mCertLoader, mCryptoProvider, false).IsNone());

    StaticArray<aos::StaticString<certhandler::cCertTypeLen>, 10> certTypes;
    auto                                                          err = client.GetCertTypes("node0", certTypes);
    ASSERT_TRUE(err.IsNone());
}

TEST_F(IAMTest, CreateKey)
{
    CertInfo clientInfo, serverInfo;

    RegisterPKCS11Module("client");
    ASSERT_TRUE(mCertHandler->SetOwner("client", cPIN).IsNone());

    RegisterPKCS11Module("server");

    ApplyCertificate("client", 0x3333444, clientInfo);
    ApplyCertificate("server", 0x3333333, serverInfo);

    IAMServer server;
    server.Init(GetServerConfig(), mCertHandler.get(), &mIdentHandler, &mPermHandler, nullptr, mCertLoader,
        mCryptoProvider, false);
    LOG_INF() << "Server initialized";

    ::iam::RemoteIAMClient client;
    ASSERT_TRUE(client.Init(GetClientConfig(), *mCertHandler, mCertLoader, mCryptoProvider, false).IsNone());

    StaticString<crypto::cCSRPEMLen> csr;
    auto                             err = client.CreateKey("node0", "server", "Aos Cloud", cPIN, csr);
    ASSERT_TRUE(err.IsNone());
}
