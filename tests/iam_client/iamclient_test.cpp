/*
 * Copyright (C) 2024 Renesas Electronics Corporation.
 * Copyright (C) 2024 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gmock/gmock.h>

#include "iam/client/iamclient.hpp"
#include "iamanager_mock.grpc.pb.h"
#include "mocks/certhandlermock.hpp"
#include "mocks/certloadermock.hpp"
#include "mocks/x509providermock.hpp"

using namespace testing;

class RemoteIAMClientMock : public iam::RemoteIAMClient {
public:
    MOCK_METHOD(iam::CertificateServiceStubPtr, CreateIAMCertificateServiceStub, (const aos::String&), (override));
    MOCK_METHOD(iam::ProvisioningServiceStubPtr, CreateIAMProvisioningServiceStub, (const aos::String&), (override));
};

class IAMClientTest : public Test {
protected:
    static constexpr const char* const cCertType          = "test-cert-type";
    static constexpr const char* const cCertUrl           = "test-cert-url";
    static constexpr const char* const cNodeId            = "test-node-1";
    static constexpr const char* const cPassword          = "test-password";
    static constexpr const char* const cPemCert           = "test-pem-cert";
    static constexpr const char* const cSubjectCommonName = "test-subj-name";

    void SetUp() override
    {
        mIAMProvisioningServiceStub = std::make_unique<iamanager::v4::MockIAMProvisioningServiceStub>();
        mIAMCertificateServiceStub  = std::make_unique<iamanager::v4::MockIAMCertificateServiceStub>();

        mConfig.mRemoteIAMs.emplace_back(RemoteIAM {"node0", "url0", UtilsTime::Duration(0)});
        mConfig.mRemoteIAMs.emplace_back(RemoteIAM {"node1", "url1", UtilsTime::Duration(0)});
    }

    RemoteIAMClientMock                                            mRemoteIAMClientMock;
    std::unique_ptr<iamanager::v4::MockIAMProvisioningServiceStub> mIAMProvisioningServiceStub;
    std::unique_ptr<iamanager::v4::MockIAMCertificateServiceStub>  mIAMCertificateServiceStub;
    Config                                                         mConfig;
    CertHandlerItfMock                                             mCertHandlerMock;
    CertLoaderItfMock                                              mCertLoaderMock;
    ProviderItfMock                                                mProviderMock;
    bool                                                           mProvisioningMode {true};
};

/***********************************************************************************************************************
 * Init tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, InitGetCertificateFails)
{
    mProvisioningMode = false;

    EXPECT_CALL(mCertHandlerMock, GetCertificate).WillOnce(Return(aos::ErrorEnum::eFailed));
    EXPECT_CALL(mCertLoaderMock, LoadCertsChainByURL).Times(0);

    auto err = mRemoteIAMClientMock.Init(mConfig, mCertHandlerMock, mCertLoaderMock, mProviderMock, mProvisioningMode);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eInvalidArgument)) << err.Message();

    const auto remoteNodes = mRemoteIAMClientMock.GetRemoteNodes();
    ASSERT_TRUE(remoteNodes.IsEmpty());
}

TEST_F(IAMClientTest, InitSucceedsInProvisioningMode)
{
    mProvisioningMode = true;

    EXPECT_CALL(mCertHandlerMock, GetCertificate).Times(0);
    EXPECT_CALL(mCertLoaderMock, LoadCertsChainByURL).Times(0);

    auto err = mRemoteIAMClientMock.Init(mConfig, mCertHandlerMock, mCertLoaderMock, mProviderMock, mProvisioningMode);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    const auto remoteNodes = mRemoteIAMClientMock.GetRemoteNodes();
    ASSERT_EQ(remoteNodes.Size(), mConfig.mRemoteIAMs.size());
}

/***********************************************************************************************************************
 * GetCertTypes tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnGetCertTypes)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub).WillOnce(Return(nullptr));

    aos::Array<aos::StaticString<aos::iam::certhandler::cCertTypeLen>> certTypes;

    const auto err = mRemoteIAMClientMock.GetCertTypes("", certTypes);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnGetCertTypes)
{
    const std::vector<std::string> cTypes = {"type1", "type2"};

    EXPECT_CALL(*mIAMProvisioningServiceStub, GetCertTypes)
        .WillOnce(Invoke(
            [nodeId = cNodeId, &cTypes](grpc::ClientContext* context, const iamanager::v4::GetCertTypesRequest& request,
                iamanager::v4::CertTypes* response) -> grpc::Status {
                (void)context;
                (void)request;
                (void)response;

                EXPECT_EQ(request.node_id(), nodeId);

                for (const auto& type : cTypes) {
                    response->add_types(type);
                }

                return grpc::Status::OK;
            }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    aos::StaticArray<aos::StaticString<aos::iam::certhandler::cCertTypeLen>, 2> certTypes;

    const auto err = mRemoteIAMClientMock.GetCertTypes(cNodeId, certTypes);
    ASSERT_TRUE(err.IsNone()) << err.Message();

    ASSERT_EQ(certTypes.Size(), cTypes.size());

    for (size_t i = 0; i < certTypes.Size(); ++i) {
        EXPECT_STREQ(certTypes[i].CStr(), cTypes[i].c_str());
    }
}

TEST_F(IAMClientTest, RPCFailedGetCertTypes)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, GetCertTypes).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    aos::StaticArray<aos::StaticString<aos::iam::certhandler::cCertTypeLen>, 1> certTypes;

    const auto err = mRemoteIAMClientMock.GetCertTypes(cNodeId, certTypes);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, NoMemoryOnGetCertTypes)
{
    const std::vector<std::string> cTypes = {"type1", "type2"};

    EXPECT_CALL(*mIAMProvisioningServiceStub, GetCertTypes)
        .WillOnce(Invoke(
            [nodeId = cNodeId, &cTypes](grpc::ClientContext* context, const iamanager::v4::GetCertTypesRequest& request,
                iamanager::v4::CertTypes* response) -> grpc::Status {
                (void)context;
                (void)request;
                (void)response;

                EXPECT_EQ(request.node_id(), nodeId);

                for (const auto& type : cTypes) {
                    response->add_types(type);
                }

                return grpc::Status::OK;
            }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    aos::StaticArray<aos::StaticString<aos::iam::certhandler::cCertTypeLen>, 1> certTypes;

    const auto err = mRemoteIAMClientMock.GetCertTypes(cNodeId, certTypes);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eNoMemory)) << err.Message();
    ASSERT_NE(certTypes.Size(), cTypes.size());
}

/***********************************************************************************************************************
 * SetOwner tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnSetOwner)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub).WillOnce(Return(nullptr));

    const auto err = mRemoteIAMClientMock.SetOwner("", "", "");
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnSetOwner)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, SetOwner)
        .WillOnce(Invoke(
            [nodeId = cNodeId, certType = cCertType, password = cPassword](grpc::ClientContext* context,
                const iamanager::v4::SetOwnerRequest& request, google::protobuf::Empty* response) -> grpc::Status {
                (void)context;
                (void)request;
                (void)response;

                EXPECT_EQ(request.node_id(), nodeId);
                EXPECT_EQ(request.type(), certType);
                EXPECT_EQ(request.password(), password);

                return grpc::Status::OK;
            }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.SetOwner(cNodeId, cCertType, cPassword);
    ASSERT_TRUE(err.IsNone()) << err.Message();
}

TEST_F(IAMClientTest, RPCFailedGetSetOwner)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, SetOwner).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.SetOwner(cNodeId, cCertType, cPassword);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

/***********************************************************************************************************************
 * Clear tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnClear)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub).WillOnce(Return(nullptr));

    const auto err = mRemoteIAMClientMock.Clear("", "");
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnClear)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, Clear)
        .WillOnce(
            Invoke([nodeId = cNodeId, certType = cCertType](grpc::ClientContext* context,
                       const iamanager::v4::ClearRequest& request, google::protobuf::Empty* response) -> grpc::Status {
                (void)context;
                (void)request;
                (void)response;

                EXPECT_EQ(request.node_id(), nodeId);
                EXPECT_EQ(request.type(), certType);

                return grpc::Status::OK;
            }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.Clear(cNodeId, cCertType);
    ASSERT_TRUE(err.IsNone()) << err.Message();
}

TEST_F(IAMClientTest, RPCFailedOnClear)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, Clear).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.Clear(cNodeId, cCertType);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

/***********************************************************************************************************************
 * CreateKey tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnCreateKey)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub).WillOnce(Return(nullptr));

    aos::StaticString<aos::crypto::cCSRPEMLen> csr;

    const auto err = mRemoteIAMClientMock.CreateKey("", "", "", "", csr);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
    ASSERT_TRUE(csr.IsEmpty());
}

TEST_F(IAMClientTest, SucceedsOnCreateKey)
{
    constexpr std::string_view cExpectedCsr {"test-csr"};

    aos::StaticString<aos::crypto::cCSRPEMLen> resultCsr;

    EXPECT_CALL(*mIAMCertificateServiceStub, CreateKey)
        .WillOnce(Invoke([nodeId = cNodeId, certType = cCertType, subjectCommonName = cSubjectCommonName,
                             password = cPassword, expectedCsr = cExpectedCsr](grpc::ClientContext* context,
                             const iamanager::v4::CreateKeyRequest&                                 request,
                             iamanager::v4::CreateKeyResponse* response) -> grpc::Status {
            (void)context;
            (void)request;
            (void)response;

            EXPECT_EQ(request.node_id(), nodeId);
            EXPECT_EQ(request.type(), certType);
            EXPECT_EQ(request.subject(), subjectCommonName);
            EXPECT_EQ(request.password(), password);

            response->set_csr(expectedCsr.data());

            return grpc::Status::OK;
        }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub)
        .WillOnce(Return(std::move(mIAMCertificateServiceStub)));

    const auto err = mRemoteIAMClientMock.CreateKey(cNodeId, cCertType, cSubjectCommonName, cPassword, resultCsr);
    ASSERT_TRUE(err.IsNone()) << err.Message();
    ASSERT_EQ(resultCsr.Size(), cExpectedCsr.length());
    ASSERT_STREQ(resultCsr.CStr(), cExpectedCsr.data());
}

TEST_F(IAMClientTest, RPCFailedOnCreateKey)
{
    aos::StaticString<aos::crypto::cCSRPEMLen> resultCsr;

    EXPECT_CALL(*mIAMCertificateServiceStub, CreateKey).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub)
        .WillOnce(Return(std::move(mIAMCertificateServiceStub)));

    const auto err = mRemoteIAMClientMock.CreateKey(cNodeId, cCertType, cSubjectCommonName, cPassword, resultCsr);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

/***********************************************************************************************************************
 * ApplyCertificate tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnApplyCertificate)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub).WillOnce(Return(nullptr));

    aos::iam::certhandler::CertInfo certInfo;

    const auto err = mRemoteIAMClientMock.ApplyCertificate("", "", "", certInfo);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnApplyCertificate)
{
    constexpr std::string_view cExpectedSerial {"test-serial"};

    aos::iam::certhandler::CertInfo resultInfo;

    EXPECT_CALL(*mIAMCertificateServiceStub, ApplyCert)
        .WillOnce(Invoke([nodeId = cNodeId, certType = cCertType, pemCert = cPemCert, certUrl = cCertUrl,
                             expectedSerial = cExpectedSerial](grpc::ClientContext* context,
                             const iamanager::v4::ApplyCertRequest&                 request,
                             iamanager::v4::ApplyCertResponse*                      response) -> grpc::Status {
            (void)context;
            (void)request;
            (void)response;

            EXPECT_EQ(request.node_id(), nodeId);
            EXPECT_EQ(request.type(), certType);
            EXPECT_EQ(request.cert(), pemCert);

            response->set_cert_url(certUrl);
            response->set_serial(expectedSerial.data());

            return grpc::Status::OK;
        }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub)
        .WillOnce(Return(std::move(mIAMCertificateServiceStub)));

    const auto err = mRemoteIAMClientMock.ApplyCertificate(cNodeId, cCertType, cPemCert, resultInfo);
    ASSERT_TRUE(err.IsNone()) << err.Message();
    ASSERT_STREQ(resultInfo.mCertURL.CStr(), cCertUrl);
    ASSERT_EQ(resultInfo.mSerial.Size(), cExpectedSerial.size());

    const std::string resultInfoSerial(resultInfo.mSerial.begin(), resultInfo.mSerial.end());
    ASSERT_EQ(resultInfoSerial, cExpectedSerial);
}

TEST_F(IAMClientTest, RPCFailedOnApplyCertificate)
{
    aos::iam::certhandler::CertInfo resultInfo;

    EXPECT_CALL(*mIAMCertificateServiceStub, ApplyCert).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub)
        .WillOnce(Return(std::move(mIAMCertificateServiceStub)));

    const auto err = mRemoteIAMClientMock.ApplyCertificate(cNodeId, cCertType, cPemCert, resultInfo);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, NoMemoryOnApplyCertificate)
{

    aos::iam::certhandler::CertInfo resultInfo;

    EXPECT_CALL(*mIAMCertificateServiceStub, ApplyCert)
        .WillOnce(Invoke([nodeId = cNodeId, certType = cCertType, pemCert = cPemCert, certUrl = cCertUrl](
                             grpc::ClientContext* context, const iamanager::v4::ApplyCertRequest& request,
                             iamanager::v4::ApplyCertResponse* response) -> grpc::Status {
            (void)context;
            (void)request;
            (void)response;

            EXPECT_EQ(request.node_id(), nodeId);
            EXPECT_EQ(request.type(), certType);
            EXPECT_EQ(request.cert(), pemCert);

            response->set_cert_url(certUrl);
            response->set_serial(std::string(aos::crypto::cSerialNumSize + 1, 'c'));

            return grpc::Status::OK;
        }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMCertificateServiceStub)
        .WillOnce(Return(std::move(mIAMCertificateServiceStub)));

    const auto err = mRemoteIAMClientMock.ApplyCertificate(cNodeId, cCertType, cPemCert, resultInfo);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eNoMemory)) << err.Message();
}

/***********************************************************************************************************************
 * EncryptDisk tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnEncryptDisk)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub).WillOnce(Return(nullptr));

    const auto err = mRemoteIAMClientMock.EncryptDisk("", "");
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnEncryptDisk)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, EncryptDisk)
        .WillOnce(Invoke(
            [nodeId = cNodeId, password = cPassword](grpc::ClientContext* context,
                const iamanager::v4::EncryptDiskRequest& request, google::protobuf::Empty* response) -> grpc::Status {
                (void)context;
                (void)request;
                (void)response;

                EXPECT_EQ(request.node_id(), nodeId);
                EXPECT_EQ(request.password(), password);

                return grpc::Status::OK;
            }));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.EncryptDisk(cNodeId, cPassword);
    ASSERT_TRUE(err.IsNone()) << err.Message();
}

TEST_F(IAMClientTest, RPCFailedOnEncryptDisk)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, EncryptDisk).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.EncryptDisk(cNodeId, cPassword);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

/***********************************************************************************************************************
 * FinishProvisioning tests
 **********************************************************************************************************************/

TEST_F(IAMClientTest, CreateStubFailsOnFinishProvisioning)
{
    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub).WillOnce(Return(nullptr));

    const auto err = mRemoteIAMClientMock.FinishProvisioning("");
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}

TEST_F(IAMClientTest, SucceedsOnFinishProvisioning)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, FinishProvisioning).WillOnce(Return(grpc::Status::OK));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.FinishProvisioning(cNodeId);
    ASSERT_TRUE(err.IsNone()) << err.Message();
}

TEST_F(IAMClientTest, RPCFailedOnFinishProvisioning)
{
    EXPECT_CALL(*mIAMProvisioningServiceStub, FinishProvisioning).WillOnce(Return(grpc::Status::CANCELLED));

    EXPECT_CALL(mRemoteIAMClientMock, CreateIAMProvisioningServiceStub)
        .WillOnce(Return(std::move(mIAMProvisioningServiceStub)));

    const auto err = mRemoteIAMClientMock.FinishProvisioning(cNodeId);
    ASSERT_TRUE(err.Is(aos::ErrorEnum::eFailed)) << err.Message();
}
